/**
 * TLS Crawler
 * <p>
 * Licensed under Apache 2.0
 * <p>
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.orchestration;

import de.rub.nds.tlscrawler.data.ScanJob;
import de.rub.nds.tlscrawler.data.ScanTarget;
import java.util.Collection;

/**
 * Orchestration provider interface.
 * Exposes methods to orchestrate TLS-Crawler instances, possibly over external
 * means, e. g. a database/api.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IOrchestrationProvider {

    /**
     * Returns all active scan jobs
     *
     * @return
     */
    Collection<ScanJob> getScanJobs();

    void putScanJob(ScanJob job);

    void deleteScanJob(ScanJob job);

    /**
     * Retrieves a scan task.
     *
     * @param job
     * @return The scan task.
     */
    String getScanTask(ScanJob job);

    /**
     * Retrieves a number of scan tasks.
     *
     * @param job
     * @param quantity Number of tasks to be retrieved.
     * @return A list of scan task IDs.
     */
    Collection<String> getScanTasks(ScanJob job, int quantity);

    long getNumberOfTasks(ScanJob job);

    void addScanTask(ScanJob job, String taskId);

    /**
     * Adds scan tasks to be distributed.
     *
     * @param job
     * @param taskIds
     */
    void addScanTasks(ScanJob job, Collection<String> taskIds);

    boolean isBlacklisted(ScanTarget target);

    void updateBlacklist();
}
