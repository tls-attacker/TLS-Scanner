/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.rub.nds.tlscrawler.data.BulkScan;
import de.rub.nds.tlscrawler.data.BulkScanJobDetails;
import de.rub.nds.tlscrawler.orchestration.RabbitMqOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The ProgressMonitor keeps track of the progress of the running bulk scans. It consumes the done notifications from
 * the workers and counts for each bulk scan how many scans are done, how many timed out and how many results were
 * written to the DB.
 */
public class ProgressMonitor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Map<String, BulkScanJobDetails> scanJobDetailsById;

    private final RabbitMqOrchestrationProvider orchestrationProvider;

    private final IPersistenceProvider persistenceProvider;

    private final Scheduler scheduler;

    private boolean listenerRegistered;

    public ProgressMonitor(RabbitMqOrchestrationProvider orchestrationProvider, IPersistenceProvider persistenceProvider, Scheduler scheduler) {
        this.scanJobDetailsById = new HashMap<>();
        this.orchestrationProvider = orchestrationProvider;
        this.persistenceProvider = persistenceProvider;
        this.scheduler = scheduler;
    }

    /**
     * Adds a listener for the done notification queue that updates the counters for the bulk scans and checks if a bulk
     * scan is finished.
     *
     * @param bulkScan
     *                 that should be monitored
     */
    public void startMonitoringBulkScanProgress(BulkScan bulkScan) {
        if (!listenerRegistered) {
            orchestrationProvider.registerDoneNotificationConsumer((consumerTag, scanJob) -> {
                String bulkScanId = scanJob.getBulkScanId();
                try {
                    if (scanJobDetailsById.containsKey(bulkScanId)) {
                        AtomicInteger counter = getScanJobDetails(bulkScanId).getDoneScanJobs();
                        switch (scanJob.getStatus()) {
                            case Timeout:
                                getScanJobDetails(bulkScanId).getScanTimeouts().incrementAndGet();
                                break;
                            case DoneResultWritten:
                                getScanJobDetails(bulkScanId).getResultsWritten().incrementAndGet();
                                break;
                        }
                        if (counter.incrementAndGet() == (bulkScan.getScanJobsPublished() != 0 ? bulkScan.getScanJobsPublished() : bulkScan.getTargetsGiven())) {
                            this.stopMonitoringAndFinalizeBulkScan(scanJob.getBulkScanId());
                        } else {
                            LOGGER.info("BulkScan '{}': {} of {} scan jobs done", bulkScanId, counter.get(),
                                (bulkScan.getScanJobsPublished() != 0 ? bulkScan.getScanJobsPublished() : bulkScan.getTargetsGiven()));
                        }
                    }
                } catch (Exception e) {
                    LOGGER.error("Exception in done notification consumer:", e);
                }
            });
            listenerRegistered = true;
        }
        BulkScanJobDetails bulkScanJobDetails = new BulkScanJobDetails(bulkScan);
        this.scanJobDetailsById.put(bulkScan.getId(), bulkScanJobDetails);
    }

    /**
     * Finishes the monitoring, updates the bulk scan in DB, sends HTTP notification if configured and shuts the controller
     * down if all bulk scans are finished.
     *
     * @param bulkScanId
     *                   of the bulk scan for which the monitoring should be stopped.
     */
    public void stopMonitoringAndFinalizeBulkScan(String bulkScanId) {
        LOGGER.info("BulkScan '{}' is finished", bulkScanId);
        BulkScanJobDetails bulkScanJobDetails = scanJobDetailsById.get(bulkScanId);
        BulkScan scan = bulkScanJobDetails.getBulkScan();
        scan.setFinished(true);
        scan.setEndTime(System.currentTimeMillis());
        scan.setResultsWritten(bulkScanJobDetails.getResultsWritten().get());
        scan.setScanTimeouts(bulkScanJobDetails.getScanTimeouts().get());
        persistenceProvider.updateBulkScan(scan);
        LOGGER.info("Persisted updated BulkScan with id: {}", scan.getId());

        scanJobDetailsById.remove(bulkScanId);

        if (scan.getNotifyUrl() != null && !scan.getNotifyUrl().isEmpty() && !scan.getNotifyUrl().isBlank()) {
            try {
                String response = notify(scan);
                LOGGER.info("BulkScan {}(id={}): sent notification to '{}' got response: '{}'", scan.getName(), scan.getId(), scan.getNotifyUrl(), response);
            } catch (IOException | InterruptedException e) {
                LOGGER.error("Could not send notification for bulkScan '{}' because: ", bulkScanId, e);
            }
        }
        try {
            if (scanJobDetailsById.isEmpty() && scheduler.isShutdown()) {
                LOGGER.info("All bulkScans are finished. Closing rabbitMq connection.");
                orchestrationProvider.closeConnection();
            }
        } catch (SchedulerException e) {
            LOGGER.error(e);
        }
    }

    /**
     * Sends an HTTP POST request containing the bulk scan object as json as body to the url that is specified for the bulk
     * scan.
     *
     * @param  bulkScan
     *                  for which a done notification request should be sent
     * @return          body of the http response as string
     */
    private static String notify(BulkScan bulkScan) throws IOException, InterruptedException {
        ObjectMapper objectMapper = new ObjectMapper();
        String requestBody = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(bulkScan);

        HttpRequest request =
            HttpRequest.newBuilder(URI.create(bulkScan.getNotifyUrl())).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(requestBody)).build();

        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString()).body();
    }

    private BulkScanJobDetails getScanJobDetails(String id) {
        return this.scanJobDetailsById.get(id);
    }
}
