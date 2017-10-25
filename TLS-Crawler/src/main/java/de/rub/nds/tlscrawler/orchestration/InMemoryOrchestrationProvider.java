/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.orchestration;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

/**
 * Simplest implementation of an orchestration provider.
 * Stores scan tasks in memory.
 * Intended for testing purposes: Single instance and no persistence.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class InMemoryOrchestrationProvider implements IOrchestrationProvider {
    private Object syncRoot = new Object();
    private List<UUID> tasks = new LinkedList<>();

    public UUID getScanTask() {
        synchronized (syncRoot) {
            return tasks.isEmpty() ? null : tasks.remove(0);
        }
    }

    @Override
    public Collection<UUID> getScanTasks(int quantity) {
        LinkedList<UUID> result = new LinkedList<>();

        synchronized (syncRoot) {
            for (int i = 0; i < quantity; i++) {
                if (!this.tasks.isEmpty()) {
                    result.add(this.tasks.remove(0));
                }
            }
        }

        return result;
    }

    public void addScanTask(UUID task) {
        synchronized (syncRoot) {
            this.tasks.add(task);
        }
    }
}
