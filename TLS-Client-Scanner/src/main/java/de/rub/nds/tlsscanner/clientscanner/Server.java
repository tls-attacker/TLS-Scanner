/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner;

import java.net.InetAddress;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsattacker.core.workflow.ThreadedServerWorkflowExecutor;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;
import de.rub.nds.tlsscanner.clientscanner.workflow.CSWorkflowExecutor;

public class Server extends Thread {
    private static int serverCounter = 0;

    private static final Logger LOGGER = LogManager.getLogger();

    private final CSWorkflowExecutor executor;

    public Server(ClientScannerConfig csconfig, IDispatcher rootDispatcher, int poolSize) {
        int i = serverCounter++;
        setName("Server-" + i);
        int corePoolSize = Math.max(poolSize / 2, 2);
        if (corePoolSize > poolSize) {
            corePoolSize = poolSize;
        }
        ThreadPoolExecutor pool = new ThreadPoolExecutor(corePoolSize, poolSize, 10, TimeUnit.MINUTES,
                new LinkedBlockingDeque<>(),
                new NamedThreadFactory("Server-" + i + "-Worker"));
        this.executor = new CSWorkflowExecutor(csconfig, rootDispatcher, pool);
    }

    public String getHostname() {
        InetAddress boundAddr = this.executor.getBoundAddress();
        if (boundAddr == null) {
            return "127.0.0.42";
        }
        return boundAddr.getHostAddress();
    }

    public int getPort() {
        return this.executor.getBoundPort();
    }

    @Override
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
