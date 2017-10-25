/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import de.rub.nds.tlscrawler.data.IScanTask;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * In-Memory implementation of a persistence provider.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class InMemoryPersistenceProvider implements IPersistenceProvider {
    private Map<UUID, IScanTask> tasks;

    public InMemoryPersistenceProvider() {
        this.tasks = new HashMap<>();
    }

    @Override
    public void save(IScanTask task) {
        this.tasks.put(task.getId(), task);
    }

    @Override
    public IScanTask getScanTask(UUID id) {
        return this.tasks.get(id);
    }

    public void printFirst(int x) {
        int i = 0;

        for (Map.Entry entry : tasks.entrySet()) {
            if (i++ > x) {
                break;
            }

            IScanTask task = (IScanTask)entry.getValue();

            String a = task.getCreatedTimestamp() == null ? "null" : task.getCreatedTimestamp().toString();
            String b = task.getCompletedTimestamp() == null ? "null" : task.getCompletedTimestamp().toString();

            System.out.println(String.format("%s %s", a, b));
        }
    }

    public void printProgress() {
        long total = this.tasks.size();
        long completed = this.tasks.entrySet().stream().map(x -> x.getValue().getCompletedTimestamp()).filter(x -> x != null).count();

        System.out.println(String.format("Finished %d/%d", completed, total));
    }
}
