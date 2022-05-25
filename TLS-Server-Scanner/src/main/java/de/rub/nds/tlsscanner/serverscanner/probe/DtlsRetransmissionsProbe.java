/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeConnectionTimeoutAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendMessagesFromLastFlightAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.DtlsRetransmissionsResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DtlsRetransmissionsProbe extends TlsServerProbe<ConfigSelector, ServerReport, DtlsRetransmissionsResult> {

    public DtlsRetransmissionsProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_RETRANSMISSIONS, configSelector);
    }

    @Override
    public DtlsRetransmissionsResult executeTest() {
        return new DtlsRetransmissionsResult(doesRetransmissions(), processesRetransmissions());
    }

    private TestResult doesRetransmissions() {
        Config config = configSelector.getBaseConfig();
        config.setAddRetransmissionsToWorkflowTraceInDtls(true);
        config.setAcceptContentRewritingDtlsFragments(true);
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        trace.addTlsAction(new ChangeConnectionTimeoutAction(3000));
        ReceiveTillAction receiveTillAction = new ReceiveTillAction(new ServerHelloDoneMessage(config));
        trace.addTlsAction(receiveTillAction);

        State state = new State(config, trace);
        executeState(state);
        if (receiveTillAction.executedAsPlanned()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult processesRetransmissions() {
        Config config = configSelector.getBaseConfig();
        config.setAddRetransmissionsToWorkflowTraceInDtls(true);
        config.setAcceptContentRewritingDtlsFragments(true);
        WorkflowTrace trace =
            new WorkflowConfigurationFactory(config).createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
        trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        trace.addTlsAction(new SendMessagesFromLastFlightAction(1));
        ReceiveTillAction receiveTillAction = new ReceiveTillAction(new ServerHelloDoneMessage(config));
        trace.addTlsAction(receiveTillAction);

        State state = new State(config, trace);
        executeState(state);
        if (receiveTillAction.executedAsPlanned()) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public DtlsRetransmissionsResult getCouldNotExecuteResult() {
        return new DtlsRetransmissionsResult(TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

}
