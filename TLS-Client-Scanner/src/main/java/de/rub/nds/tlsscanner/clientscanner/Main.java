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
import java.util.ArrayList;
import java.util.List;
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

import de.rub.nds.tlsattacker.core.certificate.CertificateByteChooser;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.client.ThreadLocalOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.ScanClientCommandConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.StandaloneCommandConfig;
import de.rub.nds.tlsscanner.clientscanner.probe.ForcedCompressionProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.FreakProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.VersionProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.downgrade.SendAlert;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.HelloReconProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SNIProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SupportedCipherSuitesProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHECompositeModulusProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHEMinimumModulusLengthProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHESmallSubgroupProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHEWeakPrivateKeyProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {
        Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.INFO);
        Configurator.setAllLevels("de.rub.nds.tlsscanner.clientscanner", Level.DEBUG);
        Patcher.applyPatches();
        {
            // suppress warnings while loading CKPs
            Level logLevel = LogManager.getLogger(CertificateKeyPair.class).getLevel();
            Configurator.setAllLevels("de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair", Level.ERROR);
            CertificateByteChooser.getInstance();
            Configurator.setAllLevels("de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair", logLevel);
        }

        GeneralDelegate generalDelegate = new GeneralDelegate();
        ClientScannerConfig csConfig = new ClientScannerConfig(generalDelegate);
        JCommander jc = csConfig.jCommander;

        try {
            jc.parse(args);
            csConfig.setParsed();
            if (csConfig.getGeneralDelegate().isHelp()) {
                jc.usage();
                return;
            }
            if (false) {
                runStandalone(csConfig);
            } else {
                runScan(csConfig);
            }
        } catch (ParameterException E) {
            LOGGER.error("Could not parse provided parameters", E);
            jc.usage();
        }
    }

    private static void runStandalone(ClientScannerConfig csConfig) {
        Server s = new Server(csConfig, new VersionProbe(null, ProtocolVersion.TLS13), 8);
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

    private static List<IProbe> getProbes(IOrchestrator orchestrator) {
        List<IProbe> probes = new ArrayList<>();
        probes.addAll(VersionProbe.getDefaultProbes(orchestrator));
        probes.add(new HelloReconProbe(orchestrator));
        probes.add(new SNIProbe());
        probes.add(new SupportedCipherSuitesProbe());
        probes.add(new DHEMinimumModulusLengthProbe(orchestrator));
        probes.addAll(DHEWeakPrivateKeyProbe.getDefaultProbes(orchestrator));
        probes.addAll(DHECompositeModulusProbe.getDefaultProbes(orchestrator));
        probes.addAll(DHESmallSubgroupProbe.getDefaultProbes(orchestrator));
        probes.add(new FreakProbe(orchestrator));
        probes.add(new ForcedCompressionProbe(orchestrator));
        probes.addAll(SendAlert.getDefaultProbes(orchestrator));
        // probes that are on todo
        if (false) {
            probes.clear();
            probes.add(new HelloReconProbe(orchestrator));
            probes.add(new SNIProbe());
            probes.add(new SupportedCipherSuitesProbe());
            probes.add(new PaddingOracleProbe(orchestrator));
        }
        if (false) {
            probes.clear();
            probes.add(new VersionProbe(orchestrator, ProtocolVersion.TLS13));
        }
        // quick scan with only the probes I am interested in right now
        if (false) {
            probes.clear();
            probes.add(new HelloReconProbe(orchestrator));
            probes.add(new SNIProbe());
            probes.add(new SupportedCipherSuitesProbe());
            probes.add(new DHEMinimumModulusLengthProbe(orchestrator));
            probes.addAll(DHEWeakPrivateKeyProbe.getDefaultProbes(orchestrator));
            probes.addAll(DHECompositeModulusProbe.getDefaultProbes(orchestrator));
            probes.addAll(DHESmallSubgroupProbe.getDefaultProbes(orchestrator));
        }
        return probes;
    }

    private static void runScan(ClientScannerConfig csConfig) {
        IOrchestrator orchestrator = new ThreadLocalOrchestrator(csConfig);
        int threads = 8;
        ThreadPoolExecutor pool = new ThreadPoolExecutor(threads, threads, 1, TimeUnit.MINUTES, new LinkedBlockingDeque<>(),
                new NamedThreadFactory("cs-probe-runner"));

        ClientScanExecutor executor = new ClientScanExecutor(getProbes(orchestrator), null, orchestrator, pool);
        ClientReport rep = executor.execute();
        pool.shutdown();

        try {
            File file = null;
            ScanClientCommandConfig scanCfg = csConfig.getSelectedSubcommand(ScanClientCommandConfig.class);
            if (scanCfg.getReportFile() != null) {
                file = new File(scanCfg.getReportFile());
            }
            JAXBContext ctx;
            ctx = JAXBContext.newInstance(ClientReport.class);
            Marshaller marsh = ctx.createMarshaller();
            marsh.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marsh.marshal(rep, System.out);
            if (file != null) {
                marsh.marshal(rep, file);
            }
        } catch (JAXBException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
