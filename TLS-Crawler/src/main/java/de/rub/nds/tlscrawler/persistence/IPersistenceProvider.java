/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import de.rub.nds.tlscrawler.data.IScanTask;

import java.util.UUID;

/**
 * Persistence provider interface.
 * Exposes methods to write out the different stages of a task
 * to a file/database/api.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IPersistenceProvider {

    /**
     * Updates the database with the scan result.
     *
     * @param task The scan task.
     */
    void save(IScanTask task);

    /**
     * Returns a scan task by ID.
     *
     * @param id The ID of the requested task.
     * @return The scan task requested by ID.
     */
    IScanTask getScanTask(UUID id);
}
