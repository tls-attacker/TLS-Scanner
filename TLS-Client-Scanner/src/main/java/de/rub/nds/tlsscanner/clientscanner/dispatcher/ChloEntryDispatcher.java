package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class ChloEntryDispatcher extends BaseExecutingDispatcher {
    private static final Logger LOGGER = LogManager.getLogger();
    protected final Dispatcher next;

    public ChloEntryDispatcher(Dispatcher next) {
        this.next = next;
    }

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        LOGGER.debug("Trying to get CHLO");
        Config config = state.getConfig();
        WorkflowTrace trace = state.getWorkflowTrace();
        config.setWorkflowExecutorShouldClose(false);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace entryTrace = factory.createTlsEntryWorkflowTrace(config.getDefaultServerConnection());
        ReceiveAction chloAction = new ReceiveAction(new ClientHelloMessage());
        entryTrace.addTlsAction(chloAction);
        extendWorkflowTraceValidatingPrefix(trace, trace, entryTrace);
        executeState(state, dispatchInformation, false);

        config.setWorkflowExecutorShouldClose(true);

        if (chloAction.getMessages().size() != 1 || !(chloAction.getMessages().get(0) instanceof ClientHelloMessage)) {
            LOGGER.error("Could not get ClientHello");
            LOGGER.error("Aborting workflow trace execution");
            return null;
        }
        ClientHelloMessage chlo = (ClientHelloMessage) chloAction.getMessages().get(0);
        LOGGER.debug("Got CHLO");
        dispatchInformation.setChlo(chlo);

        if (next != null) {
            return next.execute(state, dispatchInformation);
        }
        return null;
    }

}
