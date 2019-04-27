/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTarget;
import de.rub.nds.tlsscanner.TlsScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A reduced version of the TLS Scan, which does not test for vulnerabilities.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class FriendlyTlsScan extends TlsScan {
    private static Logger LOG = LoggerFactory.getLogger(PingScan.class);

    private static final String SCAN_NAME = "friendly_scan";

    @Override
    public String getName() {
        return this.SCAN_NAME;
    }

    @Override
    public IScanResult scan(IScanTarget target) {
        LOG.trace("scan()");

        GeneralDelegate generalDelegate = new GeneralDelegate();
   //     generalDelegate.setLogLevel(null);

        ScannerConfig config = new ScannerConfig(generalDelegate);
        config.setDangerLevel(4);
        config.setThreads(1);

        int port = 443;
        config.getClientDelegate().setHost(target.getIp() + ":" + port);

        TlsScanner scanner = new TlsScanner(config);

        SiteReport report = scanner.scan();

        return scanResultFromSiteReport(report, SCAN_NAME);
    }
}
