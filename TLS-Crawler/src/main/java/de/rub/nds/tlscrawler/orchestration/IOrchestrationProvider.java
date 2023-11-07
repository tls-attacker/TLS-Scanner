/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.orchestration;

import de.rub.nds.tlscrawler.data.ScanJob;

/**
 * Interface for the orchestration provider. Its job is to accept jobs from the controller and to
 * submit them to the worker. The provider may open a connection in its constructor, which must be
 * closed in {@link #closeConnection()}.
 */
public interface IOrchestrationProvider {

    /**
     * Submit a scan job to the orchestration provider.
     *
     * @param scanJob The scan job to be submitted.
     */
    void submitScanJob(ScanJob scanJob);

    /**
     * Register a scan job consumer. It has to confirm that the job is done using {@link
     * #notifyOfDoneScanJob(ScanJob)}.
     *
     * @param scanJobConsumer The scan job consumer to be registered.
     * @param prefetchCount Number of unacknowledged jobs that may be sent to the consumer.
     */
    void registerScanJobConsumer(ScanJobConsumer scanJobConsumer, int prefetchCount);

    /**
     * Register a done notification consumer. It is called when a scan job is done.
     *
     * @param doneNotificationConsumer The done notification consumer to be registered.
     */
    void registerDoneNotificationConsumer(DoneNotificationConsumer doneNotificationConsumer);

    /**
     * Send an acknowledgment that a scan job received by a scan consumer is finished.
     *
     * @param scanJob The scan job that is finished.
     */
    void notifyOfDoneScanJob(ScanJob scanJob);

    /** Close any connection to the orchestration provider, freeing resources. */
    void closeConnection();
}
