/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.result.CcaSupportResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class CcaSupportProbe
        extends TlsServerProbe<ConfigSelector, ServerReport, CcaSupportResult<ServerReport>> {

    public CcaSupportProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CCA_SUPPORT, configSelector);
    }

    @Override
    public CcaSupportResult executeTest() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAutoSelectCertificate(false);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.CERTIFICATE_REQUEST, state.getWorkflowTrace())) {
            return new CcaSupportResult(TestResults.TRUE);
        } else {
            return new CcaSupportResult(TestResults.FALSE);
        }
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return configSelector.foundWorkingConfig();
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    public CcaSupportResult getCouldNotExecuteResult() {
        return new CcaSupportResult(TestResults.COULD_NOT_TEST);
    }
}
