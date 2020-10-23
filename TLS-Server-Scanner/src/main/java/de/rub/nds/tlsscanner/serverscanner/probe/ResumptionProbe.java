/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
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
            return new ResumptionResult(getSessionResumption(), getIssuesSessionTicket(), getSupportsTls13PskDhe());
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new ResumptionResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                    TestResult.ERROR_DURING_TEST);
        }
    }

    private TestResult getSessionResumption() {
        try {
            Config tlsConfig = getScannerConfig().createConfig();
            tlsConfig.setQuickReceive(true);
            List<CipherSuite> ciphersuites = new LinkedList<>();
            ciphersuites.addAll(supportedSuites);
            // TODO this can fail in some rare occasions
            tlsConfig.setDefaultClientSupportedCiphersuites(ciphersuites.get(0));
            tlsConfig.setDefaultSelectedCipherSuite(tlsConfig.getDefaultClientSupportedCiphersuites().get(0));
            tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
            tlsConfig.setEnforceSettings(false);
            tlsConfig.setEarlyStop(true);
            tlsConfig.setStopActionsAfterIOException(true);
            tlsConfig.setStopReceivingAfterFatal(true);
            tlsConfig.setStopActionsAfterFatal(true);
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.FULL_RESUMPTION);
            tlsConfig.setAddECPointFormatExtension(true);
            tlsConfig.setAddEllipticCurveExtension(true);
            tlsConfig.setAddServerNameIndicationExtension(true);
            tlsConfig.setAddRenegotiationInfoExtension(true);
            tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
            tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
            State state = new State(tlsConfig);
            executeState(state);
            return state.getWorkflowTrace().executedAsPlanned() == true ? TestResult.TRUE : TestResult.FALSE;
        } catch (Exception E) {
            LOGGER.error("Could not test for support for Tls13PskDhe");
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupportsTls13PskDhe() {
        try {
            Config tlsConfig = createConfig();
            List<PskKeyExchangeMode> pskKex = new LinkedList<>();
            pskKex.add(PskKeyExchangeMode.PSK_DHE_KE);
            tlsConfig.setPSKKeyExchangeModes(pskKex);
            tlsConfig.setAddPSKKeyExchangeModesExtension(true);
            State state = new State(tlsConfig);
            WorkflowTrace trace = state.getWorkflowTrace();

            trace.addTlsAction(new ReceiveAction(tlsConfig.getDefaultClientConnection().getAlias(),
                    new NewSessionTicketMessage(false)));
            trace.addTlsAction(new ResetConnectionAction(tlsConfig.getDefaultClientConnection().getAlias()));

            tlsConfig.setAddPreSharedKeyExtension(Boolean.TRUE);
            WorkflowTrace secondHandshake = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(
                    WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);

            // remove certificate messages from 2nd handshake
            ReceiveAction firstServerMsgs = (ReceiveAction) secondHandshake.getTlsActions().get(1);
            List<ProtocolMessage> newExpectedMsgs = new LinkedList<>();
            for (ProtocolMessage msg : firstServerMsgs.getExpectedMessages()) {
                if (!(msg instanceof CertificateMessage || msg instanceof CertificateVerifyMessage)) {
                    newExpectedMsgs.add(msg);
                }
            }
            firstServerMsgs.setExpectedMessages(newExpectedMsgs);
            trace.addTlsActions(secondHandshake.getTlsActions());

            executeState(state);
            if (state.getWorkflowTrace().executedAsPlanned()) {
                return TestResult.TRUE;
            }
            return TestResult.FALSE;
        } catch (Exception E) {
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
        tlsConfig.setDefaultClientSupportedCiphersuites(CipherSuite.getTls13CipherSuites());
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
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddCertificateStatusRequestExtension(true);
        tlsConfig.setUseFreshRandom(true);
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm
                .getTls13SignatureAndHashAlgorithms());
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
            state.getWorkflowTrace().addTlsAction(
                    new ReceiveAction(tlsConfig.getDefaultClientConnection().getAlias(), new NewSessionTicketMessage(
                            false)));

            executeState(state);
            if (state.getWorkflowTrace().getLastMessageAction().executedAsPlanned()) {
                return TestResult.TRUE;
            }
            return TestResult.FALSE;
        } catch (Exception E) {
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
        return new ResumptionResult(TestResult.COULD_NOT_TEST, TestResult.NOT_TESTED_YET, TestResult.NOT_TESTED_YET);
    }
}
