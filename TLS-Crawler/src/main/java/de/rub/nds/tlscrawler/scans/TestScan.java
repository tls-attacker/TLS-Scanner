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
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlsscanner.TlsScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A simple scan using TLS Scanner to generate a site report.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TestScan implements IScan {
    private static Logger LOG = LoggerFactory.getLogger(TestScan.class);

    @Override
    public String getName() {
        return "test_scan";
    }

    @Override
    public IScanResult scan(String slaveInstanceId, IScanTarget target) {
        LOG.trace("scan()");

        ScannerConfig config = new ScannerConfig(new GeneralDelegate());
        config.setThreads(1);

        int port = 443;
        config.getClientDelegate().setHost(target.getIp() + ":" + port);

        TlsScanner scanner = new TlsScanner(config);

        SiteReport report = scanner.scan();

        IScanResult result = new ScanResult(this.getName());
        result.addString(SLAVE_INSTANCE_ID, slaveInstanceId);
        result.addString("ergebnis", report.getStringReport());

        return result;
    }
}
