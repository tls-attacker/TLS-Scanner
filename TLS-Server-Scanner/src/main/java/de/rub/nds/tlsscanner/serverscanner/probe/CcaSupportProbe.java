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
<<<<<<< HEAD
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class CcaSupportProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private TestResult supportsCca;
=======
import de.rub.nds.tlsscanner.core.probe.result.CcaSupportResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class CcaSupportProbe
        extends TlsServerProbe<ConfigSelector, ServerReport, CcaSupportResult<ServerReport>> {
>>>>>>> master

    public CcaSupportProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CCA_SUPPORT, configSelector);
        register(TlsAnalyzedProperty.SUPPORTS_CCA);
    }

    @Override
    public void executeTest() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAutoSelectCertificate(false);
        State state = new State(tlsConfig);
        executeState(state);
<<<<<<< HEAD
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE_REQUEST, state.getWorkflowTrace())) {
            supportsCca = TestResults.TRUE;
=======
        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.CERTIFICATE_REQUEST, state.getWorkflowTrace())) {
            return new CcaSupportResult(TestResults.TRUE);
>>>>>>> master
        } else {
            supportsCca = TestResults.FALSE;
        }
    }

    @Override
<<<<<<< HEAD
    public void adjustConfig(ServerReport report) {
    }
=======
    public boolean canBeExecuted(ServerReport report) {
        return configSelector.foundWorkingConfig();
    }

    @Override
    public void adjustConfig(ServerReport report) {}
>>>>>>> master

    @Override
    protected Requirement getRequirements() {
        return Requirement.NO_REQUIREMENT;
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_CCA, supportsCca);
    }
}