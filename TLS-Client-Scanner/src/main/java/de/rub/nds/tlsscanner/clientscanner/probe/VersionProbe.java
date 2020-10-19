/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.report.requirements.ProbeRequirements;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ParametrizedClientProbeResult;

public class VersionProbe extends BaseProbe {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final List<CipherSuite> suites13;
    private static final List<CipherSuite> suitesPre13;
    static {
        suitesPre13 = CipherSuite.getImplemented();
        suitesPre13.removeIf((suite) -> suite.isTLS13());
        suites13 = CipherSuite.getImplemented();
        suites13.removeIf((suite) -> !suite.isTLS13());
    }

    public static Collection<VersionProbe> getDefaultProbes(IOrchestrator orchestrator) {
        return Arrays.asList(
                new VersionProbe(orchestrator, ProtocolVersion.SSL2),
                new VersionProbe(orchestrator, ProtocolVersion.SSL3),
                new VersionProbe(orchestrator, ProtocolVersion.TLS10),
                new VersionProbe(orchestrator, ProtocolVersion.TLS11),
                new VersionProbe(orchestrator, ProtocolVersion.TLS12),
                new VersionProbe(orchestrator, ProtocolVersion.TLS13));
    }

    private final ProtocolVersion versionToTest;

    public VersionProbe(IOrchestrator orchestrator, ProtocolVersion versionToTest) {
        super(orchestrator);
        this.versionToTest = versionToTest;
    }

    @Override
    protected String getHostnamePrefix() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.versionToTest.name());
        sb.append('.');
        sb.append(super.getHostnamePrefix());
        return sb.toString();
    }

    @Override
    protected ProbeRequirements getRequirements() {
        return null;
    }

    @SuppressWarnings("squid:S3776")
    // sonarlint says this function is too complex
    // while I don't necessarily disagree, I feel that it is still okay-ish
    protected void patchTogetherFinAndApp(WorkflowTrace trace) {
        ReceiveAction recvFin = null, recvApp = null;
        for (TlsAction x : trace.getTlsActions()) {
            if (x instanceof ReceiveAction) {
                ReceiveAction ra = (ReceiveAction) x;
                if (recvFin == null) {
                    // check if we recieve FIN here
                    for (ProtocolMessage msg : ra.getExpectedMessages()) {
                        if (msg instanceof FinishedMessage) {
                            recvFin = ra;
                            break;
                        }
                    }
                } else {
                    // check if we recieve APP here
                    for (ProtocolMessage msg : ra.getExpectedMessages()) {
                        if (msg instanceof HttpsRequestMessage || msg instanceof ApplicationMessage) {
                            recvApp = ra;
                            break;
                        }
                    }
                    if (recvApp != null) {
                        break;
                    }
                }
            }
        }
        if (recvApp == null) {
            LOGGER.warn("[{}] Did not find app message in trace - results might be inaccurate", versionToTest);
        } else {
            List<ProtocolMessage> msgs = new ArrayList<>();
            msgs.addAll(recvFin.getExpectedMessages());
            msgs.addAll(recvApp.getExpectedMessages());
            recvFin.setExpectedMessages(msgs);
            trace.removeTlsAction(trace.getTlsActions().indexOf(recvApp));
        }
    }

    @Override
    public ParametrizedClientProbeResult<ProtocolVersion, Boolean> execute(State state,
            DispatchInformation dispatchInformation) throws DispatchException {
        LOGGER.debug("Testing version {}", versionToTest);
        Config config = state.getConfig();
        WorkflowTrace trace = state.getWorkflowTrace();
        config.setHighestProtocolVersion(versionToTest);
        config.setDefaultSelectedProtocolVersion(versionToTest);
        config.setDefaultApplicationMessageData("TLS Version: " + versionToTest + "\n");
        if (versionToTest == ProtocolVersion.TLS13) {
            // cf TLS-Attacker/resources/configs/tls13.config
            config.setDefaultServerSupportedCiphersuites(suites13);
            config.setDefaultSelectedCipherSuite(suites13.get(0));
            config.setAddECPointFormatExtension(false);
            config.setAddEllipticCurveExtension(true);
            config.setAddSignatureAndHashAlgorithmsExtension(true);
            config.setAddSupportedVersionsExtension(true);
            config.setAddKeyShareExtension(true);

            config.setAddRenegotiationInfoExtension(false);
            // this should already have the correct value
            // config.setDefaultServerSupportedSignatureAndHashAlgorithms
        }
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        extendWorkflowTraceToApplication(trace, config);
        if (versionToTest == ProtocolVersion.TLS13) {
            patchTogetherFinAndApp(trace);
        }
        ClientAdapterResult cres = executeState(state, dispatchInformation);
        boolean res = state.getTlsContext().getSelectedProtocolVersion() == versionToTest
                && state.getWorkflowTrace().executedAsPlanned();
        if (cres != null) {
            res = res && cres.contentShown.wasShown();
        }
        return new ParametrizedClientProbeResult<>(getClass(), versionToTest, res);
    }

}
