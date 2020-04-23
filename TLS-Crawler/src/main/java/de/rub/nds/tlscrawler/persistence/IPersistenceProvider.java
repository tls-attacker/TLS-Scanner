/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import de.rub.nds.tlscrawler.data.IPersistenceProviderStats;

import de.rub.nds.tlscrawler.data.ScanTask;
import java.util.List;

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
    void insertScanTask(ScanTask newTask);

    /**
     * Accepts new scan tasks.
     * IDs may or may not be set.
     *
     * @param newTasks The new scan tasks.
     */
    void insertScanTasks(List<ScanTask> newTasks);

    /**
     * Provides information about created tasks.
     *
     * @return The stats of this persistence provider.
     */
    IPersistenceProviderStats getStats();
}
