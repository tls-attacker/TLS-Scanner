/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlscrawler.data.IScanTarget;
import de.rub.nds.tlsscanner.TlsScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.report.SiteReport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.bson.Document;

/**
 * Scan using TLS Scanner, i. e. TLS Attacker.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TlsScan implements IScan {

    private static Logger LOG = LogManager.getLogger();

    private static String SCAN_NAME = "tls_scan";

    private final ParallelExecutor parallelExecutor;

    public TlsScan() {
        parallelExecutor = new ParallelExecutor(100, 3);
    }

    @Override
    public String getName() {
        return SCAN_NAME;
    }

    @Override
    public Document scan(IScanTarget target) {
        LOG.trace("scan()");

        GeneralDelegate generalDelegate = new GeneralDelegate();
        generalDelegate.setQuiet(true);

        ScannerConfig config = new ScannerConfig(generalDelegate);
        config.setScanDetail(ScannerDetail.NORMAL);
        config.setTimeout(2000);

        int port = 443;
        config.getClientDelegate().setHost(target.getIp() + ":" + port);
        config.getClientDelegate().setSniHostname(target.getHostname());
        config.setScanDetail(ScannerDetail.QUICK);
        TlsScanner scanner = new TlsScanner(config, parallelExecutor);
        scanner.setCloseAfterFinishParallel(false);
        if (target.getHostname() != null) {
            LOG.info("Started scanning: " + target.getHostname());
        } else {
            LOG.info("Started scanning: " + target.getIp());
        }
        SiteReport report = scanner.scan();

        if (target.getHostname() != null) {
            LOG.info("Finished scanning: " + target.getHostname());
        } else {
            LOG.info("Finished scanning: " + target.getIp());
        }
        Document document = createDocumentFromSiteReport(report);
        return document;
    }

    private Document createDocumentFromSiteReport(SiteReport report) {
        Document document = new Document();
        document.put("report", report);
        return document;
    }
}
