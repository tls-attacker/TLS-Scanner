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
import de.rub.nds.tlscrawler.data.PersistenceProviderStats;

import java.util.HashMap;
import java.util.Map;

/**
 * In-Memory implementation of a persistence provider.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class InMemoryPersistenceProvider implements IPersistenceProvider {
    private Map<String, IScanTask> tasks;

    public InMemoryPersistenceProvider() {
        this.tasks = new HashMap<>();
    }

    @Override
    public void setUpScanTask(IScanTask newTask) {
        // TODO
    }

    @Override
    public void save(IScanTask task) {
        this.tasks.put(task.getId(), task);
    }

    @Override
    public IScanTask getScanTask(String id) {
        return this.tasks.get(id);
    }

    @Override
    public IPersistenceProviderStats getStats() {
        long total = this.tasks.size();
        long completed = this.tasks.entrySet().stream().map(x -> x.getValue().getCompletedTimestamp()).filter(x -> x != null).count();

        return new PersistenceProviderStats(total, completed, null, null);
    }
}
