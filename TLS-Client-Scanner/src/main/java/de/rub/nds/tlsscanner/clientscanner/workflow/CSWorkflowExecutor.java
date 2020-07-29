package de.rub.nds.tlsscanner.clientscanner.workflow;

import java.net.Socket;
import java.net.UnknownHostException;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ThreadedServerWorkflowExecutor;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;

public class CSWorkflowExecutor extends ThreadedServerWorkflowExecutor {
    protected IDispatcher rootDispatcher;
    public CSWorkflowExecutor(State state, IDispatcher rootDispatcher) throws UnknownHostException {
        super(state);
        this.rootDispatcher = rootDispatcher;
    }

    @Override
    protected void handleClient(Socket socket) {
        pool.execute(new CSWorkflowExecutorRunnable(state, socket, this, rootDispatcher));
    }
}