/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ResumptionResult;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author robert
 */
public class ResumptionProbe extends TlsProbe {

    private List<CipherSuite> supportedSuites;

    public ResumptionProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RESUMPTION, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            return new ResumptionResult(getSessionResumption(), getIssuesSessionTicket(),
                getSupportsTls13Psk(PskKeyExchangeMode.PSK_DHE_KE), getSupportsTls13Psk(PskKeyExchangeMode.PSK_KE),
                getSupports0rtt());
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new ResumptionResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST);
        }
    }

    private TestResult getSessionResumption() {
        try {
            Config tlsConfig = getScannerConfig().createConfig();
            tlsConfig.setQuickReceive(true);
            List<CipherSuite> cipherSuites = new LinkedList<>();
            cipherSuites.addAll(supportedSuites);
            // TODO this can fail in some rare occasions
            tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites.get(0));
            tlsConfig.setDefaultSelectedCipherSuite(tlsConfig.getDefaultClientSupportedCipherSuites().get(0));
            tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
            tlsConfig.setEnforceSettings(false);
            tlsConfig.setEarlyStop(true);
            tlsConfig.setStopActionsAfterIOException(true);
            tlsConfig.setStopReceivingAfterFatal(true);
            tlsConfig.setStopActionsAfterFatal(true);
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.FULL_RESUMPTION);
            tlsConfig.setAddECPointFormatExtension(true);
            tlsConfig.setAddEllipticCurveExtension(true);
            tlsConfig.setAddRenegotiationInfoExtension(true);
            tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
            tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
            State state = new State(tlsConfig);
            executeState(state);
            return state.getWorkflowTrace().executedAsPlanned() == true ? TestResult.TRUE : TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not test for support for Tls13PskDhe");
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupportsTls13Psk(PskKeyExchangeMode exchangeMode) {
        try {
            Config tlsConfig = createConfig();
            List<PskKeyExchangeMode> pskKex = new LinkedList<>();
            pskKex.add(exchangeMode);
            tlsConfig.setPSKKeyExchangeModes(pskKex);
            if (exchangeMode == PskKeyExchangeMode.PSK_KE) {
                tlsConfig.setAddKeyShareExtension(false);
            }
            tlsConfig.setAddPSKKeyExchangeModesExtension(true);
            tlsConfig.setAddPreSharedKeyExtension(true);
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.FULL_TLS13_PSK);
            State state = new State(tlsConfig);
            executeState(state);
            MessageAction lastRcv = (MessageAction) state.getWorkflowTrace().getLastReceivingAction();
            if (lastRcv.executedAsPlanned()) {
                return TestResult.TRUE;
            }
            return TestResult.FALSE;
        } catch (Exception E) {
            LOGGER.error("Could not test for support for Tls13Psk (" + exchangeMode + ")");
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupports0rtt() {
        try {
            Config tlsConfig = createConfig();
            tlsConfig.setAddPSKKeyExchangeModesExtension(true);
            tlsConfig.setAddPreSharedKeyExtension(true);
            tlsConfig.setAddEarlyDataExtension(true);
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.FULL_ZERO_RTT);
            State state = new State(tlsConfig);
            executeState(state);

            EncryptedExtensionsMessage encExt =
                state.getWorkflowTrace().getLastReceivedMessage(EncryptedExtensionsMessage.class);
            if (encExt != null && encExt.containsExtension(ExtensionType.EARLY_DATA)) {
                return TestResult.TRUE;
            }
            return TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not test for support for Tls13PskDhe");
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private Config createConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        List<NamedGroup> tls13Groups = new LinkedList<>();
        for (NamedGroup group : NamedGroup.getImplemented()) {
            if (group.isTls13()) {
                tls13Groups.add(group);
            }
        }
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(CipherSuite.getTls13CipherSuites());
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setDefaultClientKeyShareNamedGroups(tls13Groups);
        tlsConfig.setAddCertificateStatusRequestExtension(true);
        tlsConfig.setUseFreshRandom(true);
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(
            SignatureAndHashAlgorithm.getImplementedTls13SignatureAndHashAlgorithms());
        tlsConfig.setTls13BackwardsCompatibilityMode(Boolean.TRUE);
        return tlsConfig;
    }

    private TestResult getIssuesSessionTicket() {
        try {
            Config tlsConfig = createConfig();
            List<PskKeyExchangeMode> pskKex = new LinkedList<>();
            pskKex.add(PskKeyExchangeMode.PSK_DHE_KE);
            pskKex.add(PskKeyExchangeMode.PSK_KE);
            tlsConfig.setPSKKeyExchangeModes(pskKex);
            tlsConfig.setAddPSKKeyExchangeModesExtension(true);
            State state = new State(tlsConfig);
            state.getWorkflowTrace().addTlsAction(new ReceiveAction(tlsConfig.getDefaultClientConnection().getAlias(),
                new NewSessionTicketMessage(false)));

            executeState(state);
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.NEW_SESSION_TICKET,
                state.getWorkflowTrace())) {
                return TestResult.TRUE;
            }
            return TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not test for support for Tls13SessionTickets");
            return TestResult.ERROR_DURING_TEST;
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getCipherSuites() != null && (report.getCipherSuites().size() > 0);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        if (report.getCipherSuites() != null && !report.getCipherSuites().isEmpty()) {
            supportedSuites = new ArrayList<>(report.getCipherSuites());
        } else {
            supportedSuites = CipherSuite.getImplemented();
        }
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new ResumptionResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
            TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }
}
