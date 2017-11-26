/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import de.rub.nds.tlscrawler.data.*;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

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
    public void setUpScanTasks(Collection<IScanTask> newTasks) {
        for (IScanTask task : newTasks) {
            this.setUpScanTask(task);
        }
    }

    @Override
    public void updateScanTask(IScanTask task) {
        this.tasks.put(task.getId(), task);
    }

    @Override
    public void setUpScanTask(IScanTask task) {
        this.tasks.put(task.getId(), task);
    }

    @Override
    public IScanTask getScanTask(String id) {
        return this.tasks.get(id);
    }

    @Override
    public Map<String, IScanTask> getScanTasks(Collection<String> ids) {
        throw new UnsupportedOperationException("Not implemented.");
    }

    @Override
    public IPersistenceProviderStats getStats() {
        long total = this.tasks.size();
        long completed = this.tasks.entrySet().stream()
                .map(x -> x.getValue().getCompletedTimestamp())
                .filter(Objects::nonNull)
                .count();

        return new PersistenceProviderStats(total, completed, null, null);
    }
}
