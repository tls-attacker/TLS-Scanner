/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
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
import de.rub.nds.tlsscanner.clientscanner.dispatcher.Dispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;

public class CSWorkflowExecutorRunnable extends WorkflowExecutorRunnable {
    private static final Logger LOGGER = LogManager.getLogger();
    protected final Dispatcher rootDispatcher;
    protected final ClientScannerConfig csConfig;

    public CSWorkflowExecutorRunnable(ClientScannerConfig csConfig, Socket socket,
            ThreadedServerWorkflowExecutor parent, Dispatcher rootDispatcher) {
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
        // set config defaults for further use
        config.setWorkflowExecutorShouldOpen(false);
        config.setWorkflowExecutorShouldClose(true);
        config.setResetTrace(false);
        config.setSkipExecutedActions(true);

        if (chloAction.getMessages().size() != 1 || !(chloAction.getMessages().get(0) instanceof ClientHelloMessage)) {
            LOGGER.error("Could not get ClientHello");
            LOGGER.error("Aborting workflow trace execution");
            return;
        }
        ClientHelloMessage chlo = (ClientHelloMessage) chloAction.getMessages().get(0);
        LOGGER.debug("Got CHLO");

        try {
            rootDispatcher.execute(state, new DispatchInformation(chlo));
        } catch (DispatchException e) {
            LOGGER.error("Got DispatchException", e);
        } catch (Exception e) {
            LOGGER.error("Got Exception while dispatching", e);
        }
    }
}