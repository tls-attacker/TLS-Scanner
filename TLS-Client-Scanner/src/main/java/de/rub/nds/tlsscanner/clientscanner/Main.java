/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner;

import java.io.IOException;

import javax.xml.bind.JAXBException;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;
import de.rub.nds.tlsscanner.clientscanner.probes.HelloWorldProbe;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) throws JAXBException, IOException {
        Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.INFO);
        Configurator.setAllLevels("de.rub.nds.tlsscanner.clientscanner", Level.DEBUG);
        Patcher.applyPatches();

        Config config = Config.createConfig();
        config.setWorkflowExecutorType(WorkflowExecutorType.THREADED_SERVER);
        config.setDefaultRunningMode(RunningModeType.SERVER);
        config.getDefaultServerConnection().setHostname("0.0.0.0");
        config.getDefaultServerConnection().setPort(1337);

        State state = new State(config);

        // Two threads
        // Server: Manage incoming connections
        Server s = new Server(state, new HelloWorldProbe());
        s.start();
        // (optionally) Client controller: Tell clients to connect to Server(s)

        try {
            Thread.sleep(3000);
        } catch (InterruptedException e1) {
            e1.printStackTrace();
        }
        // s.kill();
        try {
            s.join();
        } catch (InterruptedException e) {
            LOGGER.error("Failed to wait for server exit due to interrupt", e);
        }
    }
}
