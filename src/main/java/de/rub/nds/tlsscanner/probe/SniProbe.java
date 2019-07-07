/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.SniResult;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class SniProbe extends TlsProbe {

    public SniProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.SNI, scannerConfig, 0);
    }

    @Override
    public ProbeResult executeTest() {
        Config config = scannerConfig.createConfig();
        config.setAddRenegotiationInfoExtension(true);
        config.setAddServerNameIndicationExtension(false);
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        List<CipherSuite> toTestList = new LinkedList<>();
        toTestList.addAll(Arrays.asList(CipherSuite.values()));
        toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
        toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        config.setDefaultClientSupportedCiphersuites(toTestList);
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.SHORT_HELLO, RunningModeType.CLIENT);
        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
            return new SniResult(Boolean.FALSE);
        }
        //Test if we can get a hello with SNI
        config.setAddServerNameIndicationExtension(true);
        trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.CLIENT);
        state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
            return new SniResult(Boolean.TRUE);
        }
        //We cannot get a ServerHello from this Server...
        LOGGER.warn("SNI Test could not get a ServerHello message from the Server!");
        return new SniResult(null);
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return null;
    }

}
