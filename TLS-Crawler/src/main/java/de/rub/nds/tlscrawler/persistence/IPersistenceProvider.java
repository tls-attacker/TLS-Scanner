/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTask;

/**
 * Persistence provider interface.
 * Exposes methods to write out the different stages of a task
 * to a file/database/api.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IPersistenceProvider {

    /**
     * Writes a hollow result structure to the database,
     * containing the time at which the task was spawned.
     *
     * @param task The scan task.
     */
    void taskCreated(IScanTask task);

    /**
     * Updates the database with the information which node
     * accepted the task and when.
     *
     * @param task The scan task.
     */
    void taskAccepted(IScanTask task);

    /**
     * Updates the database to indicate that the scan is in progress,
     * and leaves a corresponding timestamp.
     *
     * @param task The scan task.
     */
    void taskStarted(IScanTask task);

    /**
     * Updates the database with the scan result.
     *
     * @param task The scan task.
     * @param scanResult The scan result.
     */
    void save(IScanTask task, IScanResult scanResult);
}
