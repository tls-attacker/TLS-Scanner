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
import de.rub.nds.scanner.core.probe.requirements.Requirement;
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
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DtlsRetransmissionsProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private TestResult sendsRetransmissions;
    private TestResult processesRetransmissions;

    public DtlsRetransmissionsProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_RETRANSMISSIONS, configSelector);
        super.register(TlsAnalyzedProperty.SENDS_RETRANSMISSIONS, TlsAnalyzedProperty.PROCESSES_RETRANSMISSIONS);
    }

    @Override
    public void executeTest() {
        sendsRetransmissions = doesRetransmissions();
        processesRetransmissions = processesRetransmissions();
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
    public void adjustConfig(ServerReport report) {
    }

    @Override
    protected void mergeData(ServerReport report) {
        super.put(TlsAnalyzedProperty.SENDS_RETRANSMISSIONS, sendsRetransmissions);
        super.put(TlsAnalyzedProperty.PROCESSES_RETRANSMISSIONS, processesRetransmissions);
    }

    @Override
    protected Requirement getRequirements() {
        return ProbeRequirement.NO_REQUIREMENT;
    }
}
