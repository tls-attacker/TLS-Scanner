/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.orchestration;

import de.rub.nds.tlscrawler.data.IScanTarget;
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
     * Retrieves a scan task.
     *
     * @return The scan task.
     */
    String getScanTask();

    /**
     * Retrieves a number of scan tasks.
     *
     * @param quantity Number of tasks to be retrieved.
     * @return A list of scan task IDs.
     */
    Collection<String> getScanTasks(int quantity);

    long getNumberOfTasks() throws Exception;

    void addScanTask(String taskId);

    /**
     * Adds scan tasks to be distributed.
     *
     * @param taskIds
     */
    void addScanTasks(Collection<String> taskIds);
    
    boolean isBlacklisted(IScanTarget target);
    
    public void updateBlacklist();
}
