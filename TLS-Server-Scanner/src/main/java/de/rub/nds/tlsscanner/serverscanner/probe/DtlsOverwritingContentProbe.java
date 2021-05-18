/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeContextValueAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.DtlsOverwritingContentResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DtlsOverwritingContentProbe extends TlsProbe {

    private List<VersionSuiteListPair> serverSupportedSuites;

    public DtlsOverwritingContentProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.DTLS_OVERWRITING_CONTENT, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            return new DtlsOverwritingContentResult(hasOverwritingContentBug());
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new DtlsOverwritingContentResult(TestResult.ERROR_DURING_TEST);
        }
    }

    private TestResult hasOverwritingContentBug() {
        Config config = getConfig();
        config.setAddRetransmissionsToWorkflowTrace(true);
        config.setAcceptContentRewritingDtlsFragments(true);
        config.setHighestProtocolVersion(serverSupportedSuites.get(0).getVersion());
        config.setDefaultClientSupportedCipherSuites(serverSupportedSuites.get(0).getCipherSuiteList().get(0));
        WorkflowTrace trace = new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new ChangeContextValueAction("dtlsWriteHandshakeMessageSequence", 1));
        trace.addTlsAction(new ChangeContextValueAction("serverSessionId", new byte[0]));
        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(config);
        CipherSuite secondCipherSuite = serverSupportedSuites.get(0).getCipherSuiteList().get(1);
        clientHelloMessage.setCipherSuites(Modifiable.explicit(secondCipherSuite.getByteValue()));
        trace.addTlsAction(new SendAction(clientHelloMessage));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (state.getTlsContext().getSelectedCipherSuite() == secondCipherSuite) {
            return TestResult.TRUE;
        } else {
            return TestResult.FALSE;
        }
    }

    private Config getConfig() {
        Config config = getScannerConfig().createConfig();
        List<CompressionMethod> compressionList = new ArrayList<>(Arrays.asList(CompressionMethod.values()));
        config.setDefaultClientSupportedCompressionMethods(compressionList);
        config.setEnforceSettings(false);
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        config.setAddECPointFormatExtension(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddServerNameIndicationExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        return config;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION)
            && report.isProbeAlreadyExecuted(ProbeType.CIPHER_SUITE)) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new DtlsOverwritingContentResult(TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        serverSupportedSuites = report.getVersionSuitePairs();
    }

}
