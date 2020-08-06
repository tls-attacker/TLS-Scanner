package de.rub.nds.tlsscanner.clientscanner.workflow;

import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.ThreadedServerWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorRunnable;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;

public class CSWorkflowExecutorRunnable extends WorkflowExecutorRunnable {
    private static final Logger LOGGER = LogManager.getLogger();
    protected final IDispatcher rootDispatcher;
    protected final ClientScannerConfig csConfig;

    public CSWorkflowExecutorRunnable(ClientScannerConfig csConfig, Socket socket,
            ThreadedServerWorkflowExecutor parent, IDispatcher rootDispatcher) {
        super(null, socket, parent);
        this.rootDispatcher = rootDispatcher;
        this.csConfig = csConfig;
    }

    @Override
    protected void runInternal() {
        LOGGER.debug("Trying to get CHLO");
        Config config = csConfig.createConfig();
        config.setWorkflowExecutorShouldClose(false);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultServerConnection());
        ReceiveAction chloAction = new ReceiveAction(new ClientHelloMessage());
        trace.addTlsAction(chloAction);
        State state = new State(config, trace);
        initConnectionForState(state);
        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();
        config.setWorkflowExecutorShouldOpen(false);
        config.setWorkflowExecutorShouldClose(true);

        if (chloAction.getMessages().size() != 1 || !(chloAction.getMessages().get(0) instanceof ClientHelloMessage)) {
            LOGGER.error("Could not get ClientHello");
            LOGGER.error("Aborting workflow trace execution");
            return;
        }
        ClientHelloMessage chlo = (ClientHelloMessage) chloAction.getMessages().get(0);
        LOGGER.debug("Got CHLO");
        config.setSkipFirstNActions(trace.getTlsActions().size());

        rootDispatcher.execute(state, new DispatchInformation(chlo, this.csConfig));
    }
}