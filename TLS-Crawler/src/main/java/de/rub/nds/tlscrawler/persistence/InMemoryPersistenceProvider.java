/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import de.rub.nds.tlscrawler.data.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * In-Memory implementation of a persistence provider.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class InMemoryPersistenceProvider implements IPersistenceProvider {

    private static Logger LOG = LogManager.getLogger();

    private Map<String, IScanTask> tasks;

    public InMemoryPersistenceProvider() {
        LOG.trace("Constructor()");
        this.tasks = new HashMap<>();
    }

    @Override
    public void insertScanTasks(List<ScanTask> newTasks) {
        LOG.trace("setUpScanTasks()");

        for (ScanTask task : newTasks) {
            this.insertScanTask(task);
        }
    }

    @Override
    public void insertScanTask(ScanTask task) {
        LOG.trace("setUpScanTask()");
        this.tasks.put(task.getId(), task);
    }

    @Override
    public IPersistenceProviderStats getStats() {
        LOG.trace("getStats()");

        long total = this.tasks.size();
        long completed = this.tasks.entrySet().stream()
                .map(x -> x.getValue().getCompletedTimestamp())
                .filter(Objects::nonNull)
                .count();

        return new PersistenceProviderStats(total, completed, null, null);
    }
}
