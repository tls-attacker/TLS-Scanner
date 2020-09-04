package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.BaseDispatcher;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public abstract class BaseProbe extends BaseDispatcher implements IProbe {
    private IOrchestrator orchestrator;

    public BaseProbe(IOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    @Override
    public ClientProbeResult call() throws Exception {
        return orchestrator.runProbe(this);
    }

    protected void extendWorkflowTrace(WorkflowTrace traceWithCHLO, WorkflowTraceType type, Config config) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace https_trace = factory.createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
        TlsAction traceRecvCHLO = https_trace.removeTlsAction(0);
        if (!(traceRecvCHLO instanceof ReceiveAction
                && ((ReceiveAction) traceRecvCHLO).getExpectedMessages().size() == 1
                && ((ReceiveAction) traceRecvCHLO).getExpectedMessages().get(0) instanceof ClientHelloMessage)) {
            throw new RuntimeException("Unknown first action in handshake");
        }
        traceWithCHLO.addTlsActions(https_trace.getTlsActions());
    }
}