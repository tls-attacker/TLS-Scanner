/**
 * TLS Crawler
 * <p>
 * Licensed under Apache 2.0
 * <p>
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlscrawler.data.ScanTarget;
import de.rub.nds.tlsscanner.serverscanner.TlsScanner;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import lombok.extern.log4j.Log4j2;
import org.bson.Document;

/**
 * Scan using TLS Scanner, i. e. TLS Attacker.
 *
 * @author janis.fliegenschmidt@rub.de
 */
@Log4j2
public class TlsScan implements IScan {

    private static final String SCAN_NAME = "tls_scan";

    private final ParallelExecutor parallelExecutor;

    private final int timeout;

    private final StarttlsType starttlsType;

    public TlsScan(int timeout, int parallelExecutorThreads, int reexecutions, StarttlsType starttlsType) {
        parallelExecutor = new ParallelExecutor(parallelExecutorThreads, reexecutions);
        this.timeout = timeout;
        this.starttlsType = starttlsType;
    }

    @Override
    public String getName() {
        return SCAN_NAME;
    }

    @Override
    public Document scan(ScanTarget target) {
        log.trace("scan()");

        GeneralDelegate generalDelegate = new GeneralDelegate();
        generalDelegate.setQuiet(true);

        ScannerConfig config = new ScannerConfig(generalDelegate);
        config.setScanDetail(ScannerDetail.NORMAL);
        config.setTimeout(timeout);
        config.getClientDelegate().setHost(target.getIp() + ":" + 443);
        config.getClientDelegate().setSniHostname(target.getHostname());
        config.getStarttlsDelegate().setStarttlsType(starttlsType);


        TlsScanner scanner = new TlsScanner(config, parallelExecutor);
        scanner.setCloseAfterFinishParallel(false);

        if (target.getHostname() != null) {
            log.info("Started scanning: " + target.getHostname());
        } else {
            log.info("Started scanning: " + target.getIp());
        }
        SiteReport report = scanner.scan();

        if (target.getHostname() != null) {
            log.info("Finished scanning: " + target.getHostname());
        } else {
            log.info("Finished scanning: " + target.getIp());
        }

        return createDocumentFromSiteReport(report);
    }

    private Document createDocumentFromSiteReport(SiteReport report) {
        Document document = new Document();
        document.put("report", report);
        return document;
    }

}
