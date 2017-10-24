/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.orchestration;

import de.rub.nds.tlscrawler.data.IScanTask;

import java.util.Collection;
import java.util.UUID;

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
    UUID getScanTask();

    /**
     * Retrieves a number of scan tasks.
     *
     * @param quantity Number of tasks to be retrieved.
     * @return A list of scan task IDs.
     */
    Collection<UUID> getScanTasks(int quantity);

    /**
     * Adds a scan task to be distributed to a node.
     *
     * @param task The scan task to cancel.
     */
    void addScanTask(UUID task);
}
