package de.rub.nds.tlsscanner.clientscanner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.workflow.ThreadedServerWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;
import de.rub.nds.tlsscanner.clientscanner.workflow.CSWorkflowExecutor;

public class Server extends Thread {

    private static final Logger LOGGER = LogManager.getLogger();

    private WorkflowExecutor executor;

    public Server(ClientScannerConfig csconfig, IDispatcher rootDispatcher) {
        this.executor = new CSWorkflowExecutor(csconfig, rootDispatcher);
    }

    public void run() {
        try {
            this.executor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info(
                    "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(ex.getLocalizedMessage(), ex);
        }
    }

    public void kill() {
        if (this.executor instanceof ThreadedServerWorkflowExecutor) {
            ((ThreadedServerWorkflowExecutor) this.executor).kill();
            ((ThreadedServerWorkflowExecutor) this.executor).closeSockets();
        } else {
            this.interrupt();// hope for the best?
        }
    }
}
