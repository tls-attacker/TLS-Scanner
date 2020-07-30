package de.rub.nds.tlsscanner.clientscanner.workflow;

import java.net.Socket;

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
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;

public class CSWorkflowExecutorRunnable extends WorkflowExecutorRunnable implements IStatePreparator {
    private static final Logger LOGGER = LogManager.getLogger();
    protected final IDispatcher rootDispatcher;
    protected final Config chloConfig;
    protected final ClientScannerConfig csConfig;

    public CSWorkflowExecutorRunnable(ClientScannerConfig csConfig, Socket socket,
            ThreadedServerWorkflowExecutor parent, IDispatcher rootDispatcher) {
        super(null, socket, parent);
        this.rootDispatcher = rootDispatcher;
        this.csConfig = csConfig;
        chloConfig = csConfig.createConfig();
        chloConfig.setWorkflowExecutorShouldClose(false);
    }

    @Override
    protected void runInternal() {
        LOGGER.debug("Trying to get CHLO");
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(chloConfig);
        WorkflowTrace chloTrace = factory.createTlsEntryWorkflowtrace(chloConfig.getDefaultServerConnection());
        ReceiveAction chloAction = new ReceiveAction(new ClientHelloMessage());
        chloTrace.addTlsAction(chloAction);
        State chloState = new State(chloConfig, chloTrace);
        initConnectionForState(chloState);
        WorkflowExecutor executor = new DefaultWorkflowExecutor(chloState);
        executor.executeWorkflow();

        if (chloAction.getMessages().size() != 1 || !(chloAction.getMessages().get(0) instanceof ClientHelloMessage)) {
            LOGGER.error("Could not get ClientHello");
            LOGGER.error("Aborting workflow trace execution");
            return;
        }
        ClientHelloMessage chlo = (ClientHelloMessage) chloAction.getMessages().get(0);
        LOGGER.debug("Got CHLO");

        rootDispatcher.execute(new DispatchInformation(chlo, chloState, this, this.csConfig));
    }

    @Override
    public void prepareState(State state) {
        initConnectionForState(state);
    }

    @Override
    public Config getBaseConfig() {
        return globalState.getConfig();
    }

    @Override
    public State createPreparedState(Config config, WorkflowTrace workflowTrace) {
        State ret = new State(config, workflowTrace);
        prepareState(ret);
        return ret;
    }
}