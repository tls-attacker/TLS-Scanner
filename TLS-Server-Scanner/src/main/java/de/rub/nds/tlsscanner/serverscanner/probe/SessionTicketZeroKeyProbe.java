/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.SessionTicketZeroKeyResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.ArrayUtils;

/**
 * 
 * The Probe checks for CVE-2020-13777.
 * 
 * Quote: "GnuTLS 3.6.x before 3.6.14 uses incorrect cryptography for encrypting a session ticket (a loss of
 * confidentiality in TLS 1.2, and an authentication bypass in TLS 1.3). The earliest affected version is 3.6.4
 * (2018-09-24) because of an error in a 2018-09-18 commit. Until the first key rotation, the TLS server always uses
 * wrong data in place of an encryption key derived from an application."[1]
 * 
 * Reference [1]: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13777 Reference [2]:
 * https://www.gnutls.org/security-new.html
 * 
 */
public class SessionTicketZeroKeyProbe extends TlsProbe {

    /**
     * Magic Bytes the plaintext state in GnuTls starts with
     */
    public static final byte[] GNU_TLS_MAGIC_BYTES = ArrayConverter.hexStringToByteArray("FAE1C0EA");

    /**
     * Offset of the IV according to the ticket struct in rfc5077
     */
    public static final int IV_OFFSET = 16;

    /**
     * Length of the IV according to the ticket struct in rfc5077
     */
    public static final int IV_LEN = 16;

    /**
     * Offset of the length field for the in the encrypted state according to the ticket struct in rfc5077
     */
    public static final int SESSION_STATE_LEN_FIELD_OFFSET = 32;

    /**
     * Length of the length field for the in the encrypted state according to the ticket struct in rfc5077
     */
    public static final int SESSION_STATE_LEN_FIELD_LEN = 2;

    /**
     * Offset of the encrypted state according to the ticket struct in rfc5077
     */
    public static final int SESSION_STATE_OFFSET = 34;

    private List<CipherSuite> supportedSuites;

    public SessionTicketZeroKeyProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.SESSION_TICKET_ZERO_KEY, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        State state;
        try {
            Config tlsConfig = getScannerConfig().createConfig();
            tlsConfig.setQuickReceive(true);
            List<CipherSuite> cipherSuites = new LinkedList<>();
            cipherSuites.addAll(supportedSuites);
            tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
            tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
            tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites.get(0));
            tlsConfig.setDefaultSelectedCipherSuite(tlsConfig.getDefaultClientSupportedCipherSuites().get(0));
            tlsConfig.setAddECPointFormatExtension(true);
            tlsConfig.setAddEllipticCurveExtension(true);
            tlsConfig.setAddSessionTicketTLSExtension(true);
            tlsConfig.setAddRenegotiationInfoExtension(false);
            state = new State(tlsConfig);
            executeState(state);
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new SessionTicketZeroKeyResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST);
        }

        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.NEW_SESSION_TICKET, state.getWorkflowTrace())) {
            return new SessionTicketZeroKeyResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
        }

        byte[] ticket = null;
        for (ProtocolMessage msg : WorkflowTraceUtil.getAllReceivedMessages(state.getWorkflowTrace())) {
            if (msg instanceof NewSessionTicketMessage) {
                NewSessionTicketMessage newSessionTicketMessage = (NewSessionTicketMessage) msg;
                ticket = newSessionTicketMessage.getTicket().getIdentity().getValue();
            }
        }

        byte[] key = new byte[32];
        byte[] iv;
        byte[] encryptedSessionState;
        byte[] decryptedSessionState = null;

        try {
            iv = Arrays.copyOfRange(ticket, IV_OFFSET, IV_OFFSET + IV_LEN);
            byte[] sessionStateLen = Arrays.copyOfRange(ticket, SESSION_STATE_LEN_FIELD_OFFSET,
                SESSION_STATE_LEN_FIELD_OFFSET + SESSION_STATE_LEN_FIELD_LEN);
            int sessionStateLenInt = ArrayConverter.bytesToInt(sessionStateLen);
            encryptedSessionState =
                Arrays.copyOfRange(ticket, SESSION_STATE_OFFSET, SESSION_STATE_OFFSET + sessionStateLenInt);
            Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
            SecretKey aesKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
            decryptedSessionState = cipher.doFinal(encryptedSessionState);
            LOGGER.debug("decryptedSessionState" + ArrayConverter.bytesToHexString(decryptedSessionState));
        } catch (Exception e) {
            return new SessionTicketZeroKeyResult(TestResult.FALSE, TestResult.FALSE);
        }
        TestResult hasDecryptableMasterSecret;
        TestResult hasGnuTlsMagicBytes;

        if (checkForMasterSecret(decryptedSessionState, state.getTlsContext())) {
            hasDecryptableMasterSecret = TestResult.TRUE;
        } else {
            hasDecryptableMasterSecret = TestResult.FALSE;
        }

        if (checkForGnuTlsMagicBytes(decryptedSessionState)) {
            hasGnuTlsMagicBytes = TestResult.TRUE;

        } else {
            hasGnuTlsMagicBytes = TestResult.FALSE;
        }

        return new SessionTicketZeroKeyResult(hasDecryptableMasterSecret, hasGnuTlsMagicBytes);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getCipherSuites() != null && (report.getCipherSuites().size() > 0);
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
        try {
            for (int i = 0; i < GNU_TLS_MAGIC_BYTES.length; i++) {
                if (decState[i] != GNU_TLS_MAGIC_BYTES[i]) {
                    return false;
                }
            }
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new SessionTicketZeroKeyResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportedSuites = new ArrayList<>(report.getCipherSuites());
    }

}
