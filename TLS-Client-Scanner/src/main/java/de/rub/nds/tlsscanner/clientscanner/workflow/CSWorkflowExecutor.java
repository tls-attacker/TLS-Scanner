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
import java.util.concurrent.ExecutorService;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ThreadedServerWorkflowExecutor;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.Dispatcher;

public class CSWorkflowExecutor extends ThreadedServerWorkflowExecutor {
    protected Dispatcher rootDispatcher;
    protected final ClientScannerConfig csConfig;

    public CSWorkflowExecutor(ClientScannerConfig csconfig, Dispatcher rootDispatcher, ExecutorService pool) {
        super(new State(csconfig.createConfig()), pool);
        this.rootDispatcher = rootDispatcher;
        this.csConfig = csconfig;
    }

    @Override
    protected void handleClient(Socket socket) {
        pool.execute(new CSWorkflowExecutorRunnable(csConfig, socket, this, rootDispatcher));
    }
}