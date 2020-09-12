package de.rub.nds.tlsscanner.clientscanner.probe;

import java.util.List;

import org.apache.logging.log4j.CloseableThreadContext;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
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
        try (final CloseableThreadContext.Instance ctc = CloseableThreadContext.push(getClass().getSimpleName())) {
            return orchestrator.runProbe(this);
        }
    }

    private void assertActionIsEqual(MessageAction aAction, MessageAction bAction) {
        List<ProtocolMessage> entryMsgs;
        List<ProtocolMessage> appendMsgs;
        if (aAction instanceof SendAction) {
            entryMsgs = ((SendAction) aAction).getMessages();
            appendMsgs = ((SendAction) bAction).getMessages();
        } else if (aAction instanceof ReceiveAction) {
            entryMsgs = ((ReceiveAction) aAction).getExpectedMessages();
            appendMsgs = ((ReceiveAction) bAction).getExpectedMessages();
        } else {
            throw new RuntimeException("[internal error] unknown MessageAction " + aAction);
        }
        if (entryMsgs.size() != appendMsgs.size()) {
            throw new RuntimeException("[internal error] entryTrace and actions we want to append diverge (different message count in action)" + aAction + ", " + bAction);
        }
        for (int i = 0; i < entryMsgs.size(); i++) {
            ProtocolMessage aMsg = entryMsgs.get(i);
            ProtocolMessage bMsg = appendMsgs.get(i);
            if (!aMsg.getProtocolMessageType().equals(bMsg.getProtocolMessageType())) {
                throw new RuntimeException("[internal error] entryTrace and actions we want to append diverge (different message type)" + aMsg + ", " + bMsg);
            }
        }
    }

    private void removePrefixAndAssertPrefixIsCorrect(WorkflowTrace prefixTrace, WorkflowTrace otherTrace) {
        for (TlsAction prefixAction : prefixTrace.getTlsActions()) {
            TlsAction otherAction = otherTrace.removeTlsAction(0);
            if (!prefixAction.getClass().equals(otherAction.getClass())) {
                throw new RuntimeException("[internal error] entryTrace and actions we want to append diverge (different classes)");
            }

            if (prefixAction instanceof MessageAction) {
                assertActionIsEqual((MessageAction) prefixAction, (MessageAction) otherAction);
            }
        }
    }

    protected void extendWorkflowTrace(WorkflowTrace traceWithCHLO, WorkflowTraceType type, Config config) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace entryTrace = factory.createTlsEntryWorkflowtrace(config.getDefaultServerConnection());
        entryTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
        WorkflowTrace actionsToAppend = factory.createWorkflowTrace(type, RunningModeType.SERVER);
        removePrefixAndAssertPrefixIsCorrect(entryTrace, actionsToAppend);
        traceWithCHLO.addTlsActions(actionsToAppend.getTlsActions());
    }

    protected void extendWorkflowTraceToApplication(WorkflowTrace traceWithCHLO, Config config) {
        // TODO distinguish different application layers, for now only http(s)
        extendWorkflowTrace(traceWithCHLO, WorkflowTraceType.HTTPS, config);
        config.setHttpsParsingEnabled(true);
    }
}