/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner;

import java.io.File;
import java.util.Arrays;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.client.ThreadLocalOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.HelloWorldDispatcher;
import de.rub.nds.tlsscanner.clientscanner.probe.CipherSuiteReconProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.SNIProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.VersionProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHWeakPrivateKeyProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {
        Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.INFO);
        Configurator.setAllLevels("de.rub.nds.tlsscanner.clientscanner", Level.DEBUG);
        Patcher.applyPatches();

        ClientScannerConfig csConfig = new ClientScannerConfig(new GeneralDelegate());
        JCommander commander = new JCommander(csConfig);

        try {
            commander.parse(args);
            if (csConfig.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }
            if (false) {
                runStandalone(csConfig);
            } else {
                runScan(csConfig);
            }
        } catch (ParameterException E) {
            LOGGER.error("Could not parse provided parameters", E);
            commander.usage();
        }
    }

    private static void runStandalone(ClientScannerConfig csConfig) {
        Server s = new Server(csConfig, new HelloWorldDispatcher());
        try {
            s.start();
            s.join();
        } catch (InterruptedException e) {
            LOGGER.error("Failed to wait for server exit due to interrupt", e);
            Thread.currentThread().interrupt();
        } finally {
            s.kill();
        }
    }

    private static void runScan(ClientScannerConfig csConfig) {
        csConfig.serverDelegate.setPort(0); // use any free port
        IOrchestrator orchestrator = new ThreadLocalOrchestrator(csConfig);
        ThreadPoolExecutor pool = new ThreadPoolExecutor(8, 8, 1, TimeUnit.HOURS, new LinkedBlockingDeque<>(),
                new NamedThreadFactory("cs-probe-runner"));
        ClientScanExecutor exec = new ClientScanExecutor(Arrays.asList(
                new VersionProbe(orchestrator,
                        Arrays.asList(ProtocolVersion.SSL2, ProtocolVersion.SSL3, ProtocolVersion.TLS10,
                                ProtocolVersion.TLS11, ProtocolVersion.TLS12, ProtocolVersion.TLS13)),
                new SNIProbe(orchestrator),
                new CipherSuiteReconProbe(orchestrator),
                new DHWeakPrivateKeyProbe(orchestrator)), orchestrator, pool);
        ClientReport rep = exec.execute();
        pool.shutdown();
        try {
            File file = new File("./report.xml");
            JAXBContext ctx;
            ctx = JAXBContext.newInstance(ClientReport.class);
            Marshaller marsh = ctx.createMarshaller();
            marsh.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marsh.marshal(rep, System.out);
            marsh.marshal(rep, file);
        } catch (JAXBException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
