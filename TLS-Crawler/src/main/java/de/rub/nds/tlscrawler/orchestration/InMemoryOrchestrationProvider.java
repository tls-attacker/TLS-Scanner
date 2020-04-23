/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.orchestration;

import de.rub.nds.tlscrawler.data.IScanTarget;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Simplest implementation of an orchestration provider. Stores scan tasks in
 * memory. Intended for testing purposes: Single instance and no persistence.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class InMemoryOrchestrationProvider implements IOrchestrationProvider {

    private static Logger LOG = LogManager.getLogger();

    private Object syncRoot = new Object();
    private List<String> tasks = new LinkedList<>();

    @Override
    public String getScanTask() {
        LOG.trace("getScanTask()");

        synchronized (syncRoot) {
            return tasks.isEmpty() ? null : tasks.remove(0);
        }
    }

    @Override
    public long getNumberOfTasks() throws Exception {
        throw new Exception("Option is not available");
    }

    @Override
    public Collection<String> getScanTasks(int quantity) {
        LOG.trace("getScanTasks()");

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
        LOG.trace("addScanTask()");

        synchronized (syncRoot) {
            this.tasks.add(task);
        }
    }

    @Override
    public void addScanTasks(Collection<String> taskIds) {
        throw new RuntimeException("Not yet implemented.");
    }

    @Override
    public boolean isBlacklisted(IScanTarget target) {
        return false;
    }

    @Override
    public void updateBlacklist() {
    }
}
