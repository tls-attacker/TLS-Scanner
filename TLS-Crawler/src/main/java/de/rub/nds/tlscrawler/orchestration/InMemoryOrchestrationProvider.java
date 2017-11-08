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

/**
 * Simplest implementation of an orchestration provider.
 * Stores scan tasks in memory.
 * Intended for testing purposes: Single instance and no persistence.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class InMemoryOrchestrationProvider implements IOrchestrationProvider {
    private Object syncRoot = new Object();
    private List<String> tasks = new LinkedList<>();

    @Override
    public String getScanTask() {
        synchronized (syncRoot) {
            return tasks.isEmpty() ? null : tasks.remove(0);
        }
    }

    @Override
    public Collection<String> getScanTasks(int quantity) {
        LinkedList<String> result = new LinkedList<>();

        synchronized (syncRoot) {
            for (int i = 0; i < quantity; i++) {
                if (!this.tasks.isEmpty()) {
                    result.add(this.tasks.remove(0));
                }
            }
        }

        return result;
    }

    @Override
    public void addScanTask(String task) {
        synchronized (syncRoot) {
            this.tasks.add(task);
        }
    }
}
