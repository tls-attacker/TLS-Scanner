/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlscrawler.constant.Status;
import de.rub.nds.tlscrawler.data.ScanJob;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlscrawler.orchestration.RabbitMqOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * TLS scan that uses the TLS-Scanner.
 */
public class TlsScan extends Scan {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ParallelExecutor parallelExecutor;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    public TlsScan(ScanJob scanJob, long rabbitMqAckTag, RabbitMqOrchestrationProvider orchestrationProvider, IPersistenceProvider persistenceProvider,
        int parallelExecutorThreads) {
        super(scanJob, rabbitMqAckTag, orchestrationProvider, persistenceProvider);
        this.parallelExecutor = new ParallelExecutor(parallelExecutorThreads, scanJob.getScanConfig().getReexecutions());
    }

    @Override
    public void run() {
        try {
            GeneralDelegate generalDelegate = new GeneralDelegate();
            generalDelegate.setQuiet(true);

            ServerScannerConfig config = new ServerScannerConfig(generalDelegate);
            config.setScanDetail(scanJob.getScanConfig().getScannerDetail());
            config.setTimeout(scanJob.getScanConfig().getTimeout());
            config.getClientDelegate().setHost(scanJob.getScanTarget().getIp() + ":" + scanJob.getScanTarget().getPort());
            config.getClientDelegate().setSniHostname(scanJob.getScanTarget().getHostname());
            config.getStarttlsDelegate().setStarttlsType(scanJob.getScanConfig().getStarttlsType());

            TlsServerScanner scanner = new TlsServerScanner(config, parallelExecutor);

            LOGGER.info("Started scanning '{}' ({})", scanJob.getScanTarget(), scanJob.getScanConfig().getScannerDetail());
            ServerReport report = scanner.scan();
            LOGGER.info("Finished scanning '{}' ({}) in {} s", scanJob.getScanTarget(), scanJob.getScanConfig().getScannerDetail(),
                (report.getScanEndTime() - report.getScanStartTime()) / 1000);
            if (!cancelled.get() && (report.getServerIsAlive() == null || report.getServerIsAlive())) {
                persistenceProvider.insertScanResult(new ScanResult(scanJob.getBulkScanId(), scanJob.getScanTarget(), this.createDocumentFromSiteReport(report)),
                    scanJob.getDbName(), scanJob.getCollectionName());
                scanJob.setStatus(Status.DoneResultWritten);
            } else {
                scanJob.setStatus(Status.DoneNoResult);
            }
        } catch (Throwable e) {
            LOGGER.error("Scanning of {} had to be aborted because of an exception: ", scanJob.getScanTarget(), e);
        } finally {
            this.cancel(false);
        }
    }

    @Override
    public void cancel(boolean timeout) {
        if (!cancelled.getAndSet(true)) {
            if (timeout) {
                scanJob.setStatus(Status.Timeout);
            }
            if (scanJob.isMonitored()) {
                orchestrationProvider.notifyOfDoneScanJob(scanJob);
            }
            orchestrationProvider.sendAck(rabbitMqAckTag);
            this.parallelExecutor.shutdown();
        }
    }

    private Document createDocumentFromSiteReport(ServerReport report) {
        Document document = new Document();
        document.put("report", report);
        return document;
    }

}
