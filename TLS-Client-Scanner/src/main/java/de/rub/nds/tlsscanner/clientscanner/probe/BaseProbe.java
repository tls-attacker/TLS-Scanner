package de.rub.nds.tlsscanner.clientscanner.probe;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

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
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.requirements.ProbeRequirements;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.NotExecutedResult;
import de.rub.nds.tlsscanner.clientscanner.util.helper.ReverseIterator;

public abstract class BaseProbe extends BaseDispatcher implements IProbe {
    protected static String PROBE_NAMESPACE = BaseProbe.class.getPackage().getName() + '.';
    private IOrchestrator orchestrator;
    private ProbeRequirements requirementsCache = null;
    private boolean areRequirementsChached = false;

    public BaseProbe(IOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    // #region orchestrating side
    public String getHostnameForStandalone() {
        return getHostnamePrefix();
    }

    protected String getHostnamePrefix() {
        // hostname from class path
        String prefix = getClass().getName();
        if (prefix.startsWith(PROBE_NAMESPACE)) {
            prefix = prefix.substring(PROBE_NAMESPACE.length());
        }
        // reverse segments
        String[] segments = prefix.split("\\.");
        prefix = String.join(".", new ReverseIterator<>(segments));
        return prefix;
    }

    protected ClientProbeResult callInternal(ClientReport report, String hostnamePrefix) throws InterruptedException, ExecutionException {
        return orchestrator.runProbe(this, hostnamePrefix, report.uid, report);
    }

    public final ClientProbeResult call(ClientReport report) throws InterruptedException, ExecutionException {
        try (final CloseableThreadContext.Instance ctc = CloseableThreadContext.push(getClass().getSimpleName())) {
            return callInternal(report, getHostnamePrefix());
        }
    }

    @Override
    public Callable<ClientProbeResult> getCallable(ClientReport report) {
        return () -> call(report);
    }

    protected abstract ProbeRequirements getRequirements();

    protected ProbeRequirements getRequirementsCacheControlled() {
        if (!areRequirementsChached) {
            requirementsCache = getRequirements();
            if (requirementsCache == null) {
                requirementsCache = ProbeRequirements.TRUE();
            }
            areRequirementsChached = true;
        }
        return requirementsCache;
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return getRequirementsCacheControlled().evaluateRequirementsMet(report);
    }

    @Override
    public ClientProbeResult getCouldNotExecuteResult(ClientReport report) {
        return getRequirementsCacheControlled().evaluateWhyRequirementsNotMet(getClass(), report);
    }
    // #endregion

    // #region helper functions
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
    // #endregion
}