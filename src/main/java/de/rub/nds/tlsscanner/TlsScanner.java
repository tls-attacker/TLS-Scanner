/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsattacker.attacks.connectivity.ConnectivityChecker;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.BleichenbacherProbe;
import de.rub.nds.tlsscanner.probe.CertificateProbe;
import de.rub.nds.tlsscanner.probe.CiphersuiteOrderProbe;
import de.rub.nds.tlsscanner.probe.CiphersuiteProbe;
import de.rub.nds.tlsscanner.probe.CompressionsProbe;
import de.rub.nds.tlsscanner.probe.Cve20162107Probe;
import de.rub.nds.tlsscanner.probe.DrownProbe;
import de.rub.nds.tlsscanner.probe.EarlyCcsProbe;
import de.rub.nds.tlsscanner.probe.ExtensionProbe;
import de.rub.nds.tlsscanner.probe.HeartbleedProbe;
import de.rub.nds.tlsscanner.probe.InvalidCurveProbe;
import de.rub.nds.tlsscanner.probe.MacProbe;
import de.rub.nds.tlsscanner.probe.NamedCurvesProbe;
import de.rub.nds.tlsscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.probe.PoodleProbe;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.probe.RenegotiationProbe;
import de.rub.nds.tlsscanner.probe.ResumptionProbe;
import de.rub.nds.tlsscanner.probe.SniProbe;
import de.rub.nds.tlsscanner.probe.Tls13Probe;
import de.rub.nds.tlsscanner.probe.TlsPoodleProbe;
import de.rub.nds.tlsscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.probe.TokenbindingProbe;
import de.rub.nds.tlsscanner.report.after.AfterProbe;
import de.rub.nds.tlsscanner.report.after.FreakAfterProbe;
import de.rub.nds.tlsscanner.report.after.Sweet32AfterProbe;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsScanner {

    private final ScanJobExecutor executor;
    private final ScannerConfig config;

    public TlsScanner(String websiteHost, boolean attackingScans) {
        this.executor = new ScanJobExecutor(1);
        config = new ScannerConfig(new GeneralDelegate());
        config.getGeneralDelegate().setLogLevel(Level.WARN);
        ClientDelegate clientDelegate = (ClientDelegate) config.getDelegateList().get(1);
        clientDelegate.setHost(websiteHost);
        Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.WARN);
    }

    public TlsScanner(ScannerConfig config) {
        this.executor = new ScanJobExecutor(config.getThreads());
        this.config = config;
        if (config.getGeneralDelegate().getLogLevel() == Level.ALL) {
            Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.ALL);
            Configurator.setAllLevels("de.rub.nds.modifiablevariable", Level.ALL);

        } else if (config.getGeneralDelegate().getLogLevel() == Level.TRACE) {
            Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.INFO);
            Configurator.setAllLevels("de.rub.nds.modifiablevariable", Level.INFO);
        } else {
            Configurator.setAllLevels("de.rub.nds.tlsattacker", Level.OFF);
            Configurator.setAllLevels("de.rub.nds.modifiablevariable", Level.OFF);
        }
    }

    public SiteReport scan() {
        List<TlsProbe> phaseOneTestList = new LinkedList<>();
        List<TlsProbe> phaseTwoTestList = new LinkedList<>();

        if (prechecks()) {
            phaseOneTestList.add(new SniProbe(config));
            phaseOneTestList.add(new CompressionsProbe(config));
            phaseOneTestList.add(new NamedCurvesProbe(config));
            phaseOneTestList.add(new CertificateProbe(config));
            phaseOneTestList.add(new ProtocolVersionProbe(config));
            phaseOneTestList.add(new CiphersuiteProbe(config));
            phaseOneTestList.add(new CiphersuiteOrderProbe(config));
            phaseOneTestList.add(new ExtensionProbe(config));
            phaseOneTestList.add(new Tls13Probe(config));
            phaseOneTestList.add(new TokenbindingProbe(config));
            
            phaseTwoTestList.add(new ResumptionProbe(config));
            phaseTwoTestList.add(new RenegotiationProbe(config));
            phaseTwoTestList.add(new HeartbleedProbe(config));
            phaseTwoTestList.add(new PaddingOracleProbe(config));
            phaseTwoTestList.add(new BleichenbacherProbe(config));
            phaseTwoTestList.add(new PoodleProbe(config));
            phaseTwoTestList.add(new TlsPoodleProbe(config));
            phaseTwoTestList.add(new Cve20162107Probe(config));
            phaseTwoTestList.add(new InvalidCurveProbe(config));
            phaseTwoTestList.add(new DrownProbe(config));
            phaseTwoTestList.add(new EarlyCcsProbe(config));
            phaseTwoTestList.add(new MacProbe(config));

            List<AfterProbe> afterList = new LinkedList<>();
            afterList.add(new Sweet32AfterProbe());
            afterList.add(new FreakAfterProbe());
            ScanJob job = new ScanJob(phaseOneTestList, phaseTwoTestList, afterList);
            return executor.execute(config, job);
        }
        // testList.add(new SignatureAndHashAlgorithmProbe(websiteHost));
        SiteReport report = new SiteReport(config.getClientDelegate().getHost(), new LinkedList<ProbeType>(), config.isNoColor());
        report.setServerIsAlive(false);
        return report;
    }

    public boolean prechecks() {
        Config tlsConfig = config.createConfig();
        ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
        return checker.isConnectable();
    }
}
