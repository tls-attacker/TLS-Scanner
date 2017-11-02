/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import java.time.Instant;

/**
 * Implementation of the persistence provider interface.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class PersistenceProviderStats implements IPersistenceProviderStats {
    private long totalTasks;
    private long finishedTasks;
    private Instant earliestCompletionTimestamp;
    private Instant earliestCreatedTimestamp;

    public PersistenceProviderStats(long totalTasks, long finishedTasks, Instant earliestCompletionTimestamp, Instant earliestCreatedTimestamp) {
        this.totalTasks = totalTasks;
        this.finishedTasks = finishedTasks;
        this.earliestCompletionTimestamp = earliestCompletionTimestamp;
        this.earliestCreatedTimestamp = earliestCreatedTimestamp;
    }

    @Override
    public long getTotalTasks() {
        return this.totalTasks;
    }

    @Override
    public long getFinishedTasks() {
        return this.finishedTasks;
    }

    @Override
    public Instant getEarliestCompletionTimestamp() {
        return this.earliestCompletionTimestamp;
    }

    @Override
    public Instant getEarliestCreatedTimestamp() {
        return this.earliestCreatedTimestamp;
    }

    /**
     * @param stats The stats to copy.
     * @return A threadsafe master stats copy.
     */
    public static PersistenceProviderStats copyFrom(PersistenceProviderStats stats) {
        if (stats == null) {
            throw new IllegalArgumentException("'stats' must not be null.");
        }

        return new PersistenceProviderStats(stats.getTotalTasks(),
                stats.getFinishedTasks(),
                stats.getEarliestCompletionTimestamp(),
                stats.getEarliestCreatedTimestamp());
    }
}
