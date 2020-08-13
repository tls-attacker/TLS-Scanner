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

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.IClientAdapter;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.CurlAdapter;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.LocalCommandExecutor;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.ProxiedLocalCommandExecutor;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.HelloWorldDispatcher;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) throws JAXBException, IOException, InterruptedException {
        Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.INFO);
        Configurator.setAllLevels("de.rub.nds.tlsscanner.clientscanner", Level.DEBUG);
        Patcher.applyPatches();

        ClientScannerConfig csconfig = new ClientScannerConfig(new GeneralDelegate());
        JCommander commander = new JCommander(csconfig);

        try {
            commander.parse(args);
            if (csconfig.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }
            mainInternal(csconfig);
        } catch (ParameterException E) {
            LOGGER.error("Could not parse provided parameters", E);
            commander.usage();
        }
    }

    private static void mainInternal(ClientScannerConfig csconfig) throws InterruptedException {
        // Two threads
        // Server: Manage incoming connections
        Server s = new Server(csconfig, new HelloWorldDispatcher());
        s.start();

        // (optionally) Client controller: Tell clients to connect to Server(s)
        IClientAdapter client;
        // client = new CurlAdapter(new ProxiedLocalCommandExecutor("bash", "-c"));
        client = new CurlAdapter(new LocalCommandExecutor());
        client.prepare(true);
        for (int i = 0; i < 10; i++) {
            LOGGER.info("##### {} #####", i);
            client.connect(s.getHostname(), s.getPort());
        }
        client.cleanup(true);

        try {
            s.join();
        } catch (InterruptedException e) {
            LOGGER.error("Failed to wait for server exit due to interrupt", e);
            throw e;
        }
    }
}
