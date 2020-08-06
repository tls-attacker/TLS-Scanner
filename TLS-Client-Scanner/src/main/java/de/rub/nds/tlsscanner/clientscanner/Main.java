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
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.HelloWorldDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.SNIDispatcher;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) throws JAXBException, IOException {
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

    private static void mainInternal(ClientScannerConfig csconfig) {
        // Two threads
        // Server: Manage incoming connections
        Server s = new Server(csconfig, new SNIDispatcher());
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
