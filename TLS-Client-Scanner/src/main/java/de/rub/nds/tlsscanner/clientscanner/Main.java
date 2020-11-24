/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner;

import java.util.ArrayList;
import java.util.List;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;

import de.rub.nds.tlsattacker.core.certificate.CertificateByteChooser;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.config.ExecutableSubcommand;
import de.rub.nds.tlsscanner.clientscanner.config.Subcommand;
import de.rub.nds.tlsscanner.clientscanner.probe.ForcedCompressionProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.FreakProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.Probe;
import de.rub.nds.tlsscanner.clientscanner.probe.VersionProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.Version13RandomProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.downgrade.DropConnection;
import de.rub.nds.tlsscanner.clientscanner.probe.downgrade.SendAlert;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.HelloReconProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SNIProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SupportedCipherSuitesProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHECompositeModulusProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHEMinimumModulusLengthProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHESmallSubgroupProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHEWeakPrivateKeyProbe;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {
        Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.INFO);
        Configurator.setAllLevels("de.rub.nds.tlsscanner.clientscanner", Level.DEBUG);
        new ClientScannerConfig().parseAndExecute(args);
    }

    public static List<Probe> getDefaultProbes(Orchestrator orchestrator) {
        // TODO have probes be configurable from commandline
        List<Probe> probes = new ArrayList<>();
        // .recon (add first)
        probes.add(new HelloReconProbe(orchestrator));
        probes.add(new SNIProbe());
        probes.add(new SupportedCipherSuitesProbe());
        // .downgrade
        probes.addAll(SendAlert.getDefaultProbes(orchestrator));
        probes.add(new DropConnection(orchestrator));
        // .weak.keyexchange.dhe
        probes.add(new DHEMinimumModulusLengthProbe(orchestrator));
        probes.addAll(DHEWeakPrivateKeyProbe.getDefaultProbes(orchestrator));
        probes.addAll(DHECompositeModulusProbe.getDefaultProbes(orchestrator));
        probes.addAll(DHESmallSubgroupProbe.getDefaultProbes(orchestrator));
        // .
        probes.add(new ForcedCompressionProbe(orchestrator));
        probes.add(new FreakProbe(orchestrator));
        probes.addAll(PaddingOracleProbe.getDefaultProbes(orchestrator));
        probes.addAll(VersionProbe.getDefaultProbes(orchestrator));
        probes.addAll(Version13RandomProbe.getDefaultProbes(orchestrator));

        return probes;
    }
}
