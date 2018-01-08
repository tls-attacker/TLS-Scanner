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
import de.rub.nds.tlsscanner.probe.ExtensionProbe;
import de.rub.nds.tlsscanner.probe.HeartbleedProbe;
import de.rub.nds.tlsscanner.probe.InvalidCurveProbe;
import de.rub.nds.tlsscanner.probe.NamedCurvesProbe;
import de.rub.nds.tlsscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.probe.PoodleProbe;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.probe.TlsPoodleProbe;
import de.rub.nds.tlsscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.report.after.AfterProbe;
import de.rub.nds.tlsscanner.report.after.DrownAfterProbe;
import de.rub.nds.tlsscanner.report.after.Sweet32AfterProbe;
import java.util.ArrayList;
import java.util.Arrays;
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
        List<TlsProbe> testList = new LinkedList<>();

        if (prechecks()) {
            testList.add(new NamedCurvesProbe(config));
            testList.add(new CertificateProbe(config));
            testList.add(new ProtocolVersionProbe(config));
            testList.add(new CiphersuiteProbe(config));
            testList.add(new CiphersuiteOrderProbe(config));
            testList.add(new HeartbleedProbe(config));
            testList.add(new PaddingOracleProbe(config));
            testList.add(new BleichenbacherProbe(config));
            testList.add(new PoodleProbe(config));
            testList.add(new TlsPoodleProbe(config));
            testList.add(new Cve20162107Probe(config));
            testList.add(new InvalidCurveProbe(config));
            testList.add(new ExtensionProbe(config));
            testList.add(new CompressionsProbe(config));
            List<AfterProbe> afterList = new LinkedList<>();
            afterList.add(new Sweet32AfterProbe());
            afterList.add(new DrownAfterProbe());
            ScanJob job = new ScanJob(testList, afterList);
            return executor.execute(config, job);
        }
        // testList.add(new SignatureAndHashAlgorithmProbe(websiteHost));
        SiteReport report = new SiteReport(config.getClientDelegate().getHost(), new LinkedList<ProbeType>());
        report.setServerIsAlive(false);
        return report;
    }

    public boolean prechecks() {
        Config tlsConfig = config.createConfig();
        ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
        return checker.isConnectable();
    }

}
