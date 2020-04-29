/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.orchestration;

import de.rub.nds.tlscrawler.data.IScanTarget;
import de.rub.nds.tlscrawler.data.ScanJob;
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
     */
    Collection<ScanJob> getScanJobs();
    
    /**
     * Retrieves a scan task.
     *
     * @return The scan task.
     */
    String getScanTask(ScanJob job);

    /**
     * Retrieves a number of scan tasks.
     *
     * @param quantity Number of tasks to be retrieved.
     * @return A list of scan task IDs.
     */
    public Collection<String> getScanTasks(ScanJob job, int quantity);

    public long getNumberOfTasks(ScanJob job);

    public void addScanTask(ScanJob job, String taskId);

    /**
     * Adds scan tasks to be distributed.
     *
     * @param taskIds
     */
    public void addScanTasks(ScanJob job, Collection<String> taskIds);
    
    public boolean isBlacklisted(IScanTarget target);
    
    public void updateBlacklist();
}
