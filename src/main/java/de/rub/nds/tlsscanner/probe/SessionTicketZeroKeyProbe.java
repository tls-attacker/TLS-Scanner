/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.SessionTicketZeroKeyResult;

public class SessionTicketZeroKeyProbe extends TlsProbe {

    public static final byte[] GNU_TLS_MAGIC_BYTES = ArrayConverter.hexStringToByteArray("FAE1C0EA");
    public static final int IV_OFFSET = 16;
    public static final int IV_LEN = 16;
    public static final int SESSION_STATE_LENFIELD_OFFSET = 32;
    public static final int SESSION_STATE_LENFIELD_LEN = 2;
    public static final int SESSION_STATE__OFFSET = 34;
    private List<CipherSuite> supportedSuites;

    public SessionTicketZeroKeyProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.SESSION_TICKET_ZERO_KEY, scannerConfig, 0);
    }

    public SessionTicketZeroKeyProbe(ParallelExecutor parallelExecutor, ProbeType type, ScannerConfig scannerConfig,
            int danger) {
        super(parallelExecutor, type, scannerConfig, danger);
    }

    @Override
    public ProbeResult executeTest() {
        State state;
        try {
            Config tlsConfig = getScannerConfig().createConfig();
            tlsConfig.setQuickReceive(true);
            List<CipherSuite> ciphersuites = new LinkedList<>();
            ciphersuites.addAll(supportedSuites);
            tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
            tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
            tlsConfig.setDefaultClientSupportedCiphersuites(ciphersuites.get(0));
            tlsConfig.setDefaultSelectedCipherSuite(tlsConfig.getDefaultClientSupportedCiphersuites().get(0));
            tlsConfig.setAddECPointFormatExtension(true);
            tlsConfig.setAddEllipticCurveExtension(true);
            tlsConfig.setAddSessionTicketTLSExtension(true);
            tlsConfig.setAddServerNameIndicationExtension(true);
            tlsConfig.setAddRenegotiationInfoExtension(false);
            state = new State(tlsConfig);
            executeState(state);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new SessionTicketZeroKeyResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                    TestResult.ERROR_DURING_TEST);
        }

        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.NEW_SESSION_TICKET, state.getWorkflowTrace())) {
            return new SessionTicketZeroKeyResult(TestResult.UNSUPPORTED, TestResult.UNSUPPORTED,
                    TestResult.UNSUPPORTED);
        }

        byte[] ticket = null;
        for (ProtocolMessage msg : WorkflowTraceUtil.getAllReceivedMessages(state.getWorkflowTrace())) {
            if (msg instanceof NewSessionTicketMessage) {
                NewSessionTicketMessage newSessionTicketMessage = (NewSessionTicketMessage) msg;
                ticket = newSessionTicketMessage.getTicket().getIdentity().getValue();
            }
        }

        byte[] key = ArrayConverter
                .hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000");
        byte[] iv, encryptedSessionState;
        byte[] decryptedSessionState = null;

        try {
            iv = Arrays.copyOfRange(ticket, IV_OFFSET, IV_OFFSET + IV_LEN);
            byte[] sessionStateLen = Arrays.copyOfRange(ticket, SESSION_STATE_LENFIELD_OFFSET,
                    SESSION_STATE_LENFIELD_OFFSET + SESSION_STATE_LENFIELD_LEN);
            int sessionStateLenInt = ArrayConverter.bytesToInt(sessionStateLen);
            encryptedSessionState = Arrays.copyOfRange(ticket, SESSION_STATE__OFFSET, SESSION_STATE__OFFSET
                    + sessionStateLenInt);
            Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
            SecretKey aesKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
            decryptedSessionState = cipher.doFinal(encryptedSessionState);
            LOGGER.debug("decryptedSsessionState" + ArrayConverter.bytesToHexString(decryptedSessionState));
        } catch (Exception e) {
            return new SessionTicketZeroKeyResult(TestResult.FALSE, TestResult.FALSE, TestResult.FALSE);
        }
        TestResult hasCorrectPadding = TestResult.TRUE;
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

        return new SessionTicketZeroKeyResult(hasCorrectPadding, hasDecryptableMasterSecret, hasGnuTlsMagicBytes);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getCipherSuites() != null && (report.getCipherSuites().size() > 0);
    }

    private boolean checkForMasterSecret(byte[] decState, TlsContext context) {
        boolean found = false;
        byte[] ms = context.getMasterSecret();
        for (int i = 0; i < decState.length - ms.length; i++) {
            found = true;
            for (int j = 0; j < ms.length; j++) {
                if (decState[i + j] != ms[j]) {
                    found = false;
                    break;
                }
            }
            if (found)
                return true;
        }
        return false;
    }

    private boolean checkForGnuTlsMagicBytes(byte[] decState) {
        try {
            for (int i = 0; i < GNU_TLS_MAGIC_BYTES.length; i++)
                if (decState[i] != GNU_TLS_MAGIC_BYTES[i])
                    return false;
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new SessionTicketZeroKeyResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
                TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        if (report.getCipherSuites() != null && !report.getCipherSuites().isEmpty()) {
            supportedSuites = new ArrayList<>(report.getCipherSuites());

        } else {
            supportedSuites = CipherSuite.getImplemented();
        }
    }

}
