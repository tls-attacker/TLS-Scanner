package de.rub.nds.tlsscanner.clientscanner.workflow;

import java.net.Socket;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ThreadedServerWorkflowExecutor;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;

public class CSWorkflowExecutor extends ThreadedServerWorkflowExecutor {
    protected IDispatcher rootDispatcher;
    protected final ClientScannerConfig csConfig;

    public CSWorkflowExecutor(ClientScannerConfig csconfig, IDispatcher rootDispatcher) {
        super(new State(csconfig.createConfig()));
        this.rootDispatcher = rootDispatcher;
        this.csConfig = csconfig;
    }

    @Override
    protected void handleClient(Socket socket) {
        pool.execute(new CSWorkflowExecutorRunnable(csConfig, socket, this, rootDispatcher));
    }
}