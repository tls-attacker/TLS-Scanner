/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.core.probe.requirements.PropertyRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.ArrayUtils;

/**
 * The Probe checks for CVE-2020-13777.
 *
 * <p>Quote: "GnuTLS 3.6.x before 3.6.14 uses incorrect cryptography for encrypting a session ticket
 * (a loss of confidentiality in TLS 1.2, and an authentication bypass in TLS 1.3). The earliest
 * affected version is 3.6.4 (2018-09-24) because of an error in a 2018-09-18 commit. Until the
 * first key rotation, the TLS server always uses wrong data in place of an encryption key derived
 * from an application."[1]
 *
 * <p>Reference [1]: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13777 Reference [2]:
 * https://www.gnutls.org/security-new.html
 */
public class SessionTicketZeroKeyProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    /** Magic Bytes the plaintext state in GnuTls starts with */
    public static final byte[] GNU_TLS_MAGIC_BYTES =
            ArrayConverter.hexStringToByteArray("FAE1C0EA");

    /** Offset of the IV according to the ticket struct in rfc5077 */
    public static final int IV_OFFSET = 16;

    /** Length of the IV according to the ticket struct in rfc5077 */
    public static final int IV_LEN = 16;

    /**
     * Offset of the length field for the in the encrypted state according to the ticket struct in
     * rfc5077
     */
    public static final int SESSION_STATE_LEN_FIELD_OFFSET = 32;

    /**
     * Length of the length field for the in the encrypted state according to the ticket struct in
     * rfc5077
     */
    public static final int SESSION_STATE_LEN_FIELD_LEN = 2;

    /** Offset of the encrypted state according to the ticket struct in rfc5077 */
    public static final int SESSION_STATE_OFFSET = 34;

    private TestResult hasDecryptableMasterSecret = TestResults.COULD_NOT_TEST;
    private TestResult hasGnuTlsMagicBytes = TestResults.COULD_NOT_TEST;

    public SessionTicketZeroKeyProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.SESSION_TICKET_ZERO_KEY, configSelector);
        register(
                TlsAnalyzedProperty.VULNERABLE_TO_SESSION_TICKET_ZERO_KEY,
                TlsAnalyzedProperty.HAS_GNU_TLS_MAGIC_BYTES);
    }

    @Override
    public void executeTest() {
        State state;
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setAddSessionTicketTLSExtension(true);
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(tlsConfig)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(
                new ReceiveAction(
                        new NewSessionTicketMessage(),
                        new ChangeCipherSpecMessage(),
                        new FinishedMessage()));
        state = new State(tlsConfig, trace);
        executeState(state);

        if (!WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.NEW_SESSION_TICKET, state.getWorkflowTrace())) {
            hasDecryptableMasterSecret = hasGnuTlsMagicBytes = TestResults.COULD_NOT_TEST;
            return;
        }

        byte[] ticket = null;
        for (ProtocolMessage<?> msg :
                WorkflowTraceUtil.getAllReceivedMessages(state.getWorkflowTrace())) {
            if (msg instanceof NewSessionTicketMessage) {
                NewSessionTicketMessage newSessionTicketMessage = (NewSessionTicketMessage) msg;
                ticket = newSessionTicketMessage.getTicket().getIdentity().getValue();
            }
        }

        byte[] key = new byte[32];
        byte[] iv;
        byte[] encryptedSessionState;
        byte[] decryptedSessionState = null;

        iv = Arrays.copyOfRange(ticket, IV_OFFSET, IV_OFFSET + IV_LEN);
        byte[] sessionStateLen =
                Arrays.copyOfRange(
                        ticket,
                        SESSION_STATE_LEN_FIELD_OFFSET,
                        SESSION_STATE_LEN_FIELD_OFFSET + SESSION_STATE_LEN_FIELD_LEN);
        int sessionStateLenInt = ArrayConverter.bytesToInt(sessionStateLen);
        encryptedSessionState =
                Arrays.copyOfRange(
                        ticket, SESSION_STATE_OFFSET, SESSION_STATE_OFFSET + sessionStateLenInt);
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
            SecretKey aesKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
            decryptedSessionState = cipher.doFinal(encryptedSessionState);
        } catch (InvalidAlgorithmParameterException
                | NoSuchPaddingException
                | IllegalBlockSizeException
                | NoSuchAlgorithmException
                | BadPaddingException
                | InvalidKeyException e) {
            LOGGER.debug(e);
            hasDecryptableMasterSecret = hasGnuTlsMagicBytes = TestResults.FALSE;
            return;
        }
        LOGGER.debug(
                "decryptedSessionState" + ArrayConverter.bytesToHexString(decryptedSessionState));
        TestResult hasDecryptableMasterSecret;
        TestResult hasGnuTlsMagicBytes;
        if (checkForMasterSecret(decryptedSessionState, state.getTlsContext())) {
            hasDecryptableMasterSecret = TestResults.TRUE;
        } else {
            hasDecryptableMasterSecret = TestResults.FALSE;
        }
        if (checkForGnuTlsMagicBytes(decryptedSessionState)) {
            hasGnuTlsMagicBytes = TestResults.TRUE;
        } else {
            hasGnuTlsMagicBytes = TestResults.FALSE;
        }
    }

    @Override
    public Requirement getRequirements() {
        return new PropertyRequirement(TlsAnalyzedProperty.SUPPORTS_SESSION_TICKETS)
                .requires(new ProbeRequirement(TlsProbeType.EXTENSIONS));
    }

    private boolean checkForMasterSecret(byte[] decState, TlsContext context) {
        List<Byte> target = Arrays.asList(ArrayUtils.toObject(context.getMasterSecret()));
        List<Byte> source = Arrays.asList(ArrayUtils.toObject(decState));
        if (Collections.indexOfSubList(source, target) == -1) {
            return false;
        }
        return true;
    }

    private boolean checkForGnuTlsMagicBytes(byte[] decState) {
        for (int i = 0; i < GNU_TLS_MAGIC_BYTES.length; i++) {
            if (decState[i] != GNU_TLS_MAGIC_BYTES[i]) {
                return false;
            }
        }
        return true;
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.VULNERABLE_TO_SESSION_TICKET_ZERO_KEY, hasDecryptableMasterSecret);
        put(TlsAnalyzedProperty.HAS_GNU_TLS_MAGIC_BYTES, hasGnuTlsMagicBytes);
    }
}
