/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import de.rub.nds.tlscrawler.data.IPersistenceProviderStats;
import de.rub.nds.tlscrawler.data.IScanTask;

import java.util.Collection;
import java.util.Map;

/**
 * Persistence provider interface.
 * Exposes methods to write out the different stages of a task
 * to a file/database/api.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IPersistenceProvider {

    /**
     * Accepts new scan task.
     * ID may or may not be set.
     *
     * @param newTask The new scan task.
     */
    void setUpScanTask(IScanTask newTask);

    /**
     * Accepts new scan tasks.
     * IDs may or may not be set.
     *
     * @param newTasks The new scan tasks.
     */
    void setUpScanTasks(Collection<IScanTask> newTasks);

    /**
     *  Updates the database with the scan result.
     *
     * @param task The scan task with all fields present.
     */
    void updateScanTask(IScanTask task);

    /**
     * Returns a scan task by ID.
     *
     * @param id The ID of the requested task.
     * @return The scan task requested by ID.
     */
    IScanTask getScanTask(String id);

    /**
     * Bulk-returns scan tasks by ID.
     * @param ids The ids of the requested scans.
     * @return The requested scan tasks by ID.
     */
    Map<String, IScanTask> getScanTasks(Collection<String> ids);

    /**
     * Provides information about created tasks.
     *
     * @return The stats of this persistence provider.
     */
    IPersistenceProviderStats getStats();
}
