/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import de.rub.nds.tlscrawler.data.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    private static Logger LOG = LoggerFactory.getLogger(InMemoryPersistenceProvider.class);

    private Map<String, IScanTask> tasks;

    public InMemoryPersistenceProvider() {
        LOG.trace("Constructor()");
        this.tasks = new HashMap<>();
    }

    @Override
    public void setUpScanTasks(Collection<IScanTask> newTasks) {
        LOG.trace("setUpScanTasks()");

        for (IScanTask task : newTasks) {
            this.setUpScanTask(task);
        }
    }

    @Override
    public void setUpScanTask(IScanTask task) {
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
