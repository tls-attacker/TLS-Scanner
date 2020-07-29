package de.rub.nds.tlsscanner.clientscanner.workflow;

import java.net.Socket;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.ThreadedServerWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorRunnable;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;

public class CSWorkflowExecutorRunnable extends WorkflowExecutorRunnable {
    private static final Logger LOGGER = LogManager.getLogger();
    protected final IDispatcher rootDispatcher;
    protected final Config chloConfig;

    public CSWorkflowExecutorRunnable(State globalState, Socket socket, ThreadedServerWorkflowExecutor parent, IDispatcher rootDispatcher) {
        super(globalState, socket, parent);
        this.rootDispatcher = rootDispatcher;
        //just assume no one changes the config after the constructor
        chloConfig = globalState.getConfig().createCopy();
        chloConfig.setWorkflowExecutorShouldClose(false);
    }

    @Override
    protected void runInternal() {
        LOGGER.debug("Trying to get CHLO");
        WorkflowTrace getChloTrace = new WorkflowTrace();
        //TODO allow for custom get CHLO trace; e.g. for FTPs
        ReceiveAction getChloAction = new ReceiveAction(new ClientHelloMessage());
        getChloTrace.addTlsAction(getChloAction);
        State chloState = execute(getChloTrace, chloConfig, null);

        if (getChloAction.getMessages().size() != 1
                || !(getChloAction.getMessages().get(0) instanceof ClientHelloMessage)) {
            LOGGER.error("Could not get ClientHello");
            LOGGER.error("Aborting workflow trace execution");
            return;
        }
        ClientHelloMessage chlo = (ClientHelloMessage) getChloAction.getMessages().get(0);
        LOGGER.debug("Got CHLO");

        WorkflowTrace mainTrace = new WorkflowTrace();
        mainTrace.addTlsAction(new DummyGetClientHelloAction(chlo));
        rootDispatcher.fillTrace(mainTrace, chloState);
        execute(mainTrace, globalState.getConfig(), chloState.getAllTlsContexts());
    }

    protected State execute(WorkflowTrace trace, Config config, List<TlsContext> contexts) {
        State state = new State(config, trace);
        initConnectionForState(state);
        if (contexts != null) {
            for (TlsContext ctx : contexts) {
                state.replaceTlsContext(ctx);
            }
        }
        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();
        return state;
    }
}