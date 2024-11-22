/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.FulfilledRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class SniProbe extends TlsServerProbe {

    private TestResult requiresSni = TestResults.COULD_NOT_TEST;

    public SniProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.SNI, configSelector);
        register(TlsAnalyzedProperty.REQUIRES_SNI);
    }

    @Override
    protected void executeTest() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        config.setAddServerNameIndicationExtension(false);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        State state = new State(config);
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
            requiresSni = TestResults.FALSE;
            return;
        }
        // Test if we can get a hello with SNI
        config.setAddServerNameIndicationExtension(true);
        state = new State(config);
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
            requiresSni = TestResults.TRUE;
            return;
        }
        // We cannot get a ServerHello from this Server...
        LOGGER.debug("SNI Test could not get a ServerHello message from the Server!");
        requiresSni = TestResults.UNCERTAIN;
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.REQUIRES_SNI, requiresSni);
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new FulfilledRequirement<>();
    }
}
