/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class SniProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private TestResult requiresSni;

    public SniProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.SNI, configSelector);
        register(TlsAnalyzedProperty.REQUIRES_SNI);
    }

    @Override
<<<<<<< HEAD
    public void executeTest() {
        Config config = configSelector.getBaseConfig();
=======
    public SniResult executeTest() {
        Config config = configSelector.getAnyWorkingBaseConfig();
>>>>>>> master
        config.setAddServerNameIndicationExtension(false);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        State state = new State(config);
        executeState(state);
<<<<<<< HEAD
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            requiresSni = TestResults.FALSE;
            return;
=======
        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return new SniResult(TestResults.FALSE);
>>>>>>> master
        }
        // Test if we can get a hello with SNI
        config.setAddServerNameIndicationExtension(true);
        state = new State(config);
        executeState(state);
<<<<<<< HEAD
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            requiresSni = TestResults.TRUE;
            return;
=======
        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return new SniResult(TestResults.TRUE);
>>>>>>> master
        }
        // We cannot get a ServerHello from this Server...
        LOGGER.debug("SNI Test could not get a ServerHello message from the Server!");
        requiresSni = TestResults.UNCERTAIN;
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.REQUIRES_SNI, requiresSni);
    }

<<<<<<< HEAD
    public void adjustConfig(ServerReport report) {
    }
=======
    @Override
    public void adjustConfig(ServerReport report) {}
>>>>>>> master

    @Override
    protected Requirement getRequirements() {
        return Requirement.NO_REQUIREMENT;
    }
}
