/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

/**
 * Implementation of the slave stats interface.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class SlaveStats implements ISlaveStats {
    private long acceptedTaskCount;
    private long completedTaskCount;

    public SlaveStats(long acceptedTaskCount, long completedTaskCount) {
        this.acceptedTaskCount = acceptedTaskCount;
        this.completedTaskCount = completedTaskCount;
    }

    @Override
    public long getAcceptedTasksCount() {
        return this.acceptedTaskCount;
    }

    @Override
    public long getCompletedTasksCount() {
        return this.completedTaskCount;
    }

    public void incrementAcceptedTaskCount(long increment) {
        this.acceptedTaskCount += increment;
    }

    public void incrementCompletedTaskCount(long increment) {
        this.completedTaskCount += increment;
    }

    /**
     * @param stats The stats to copy.
     * @return A threadsafe slave stats copy.
     */
    public static SlaveStats copyFrom(ISlaveStats stats) {
        if (stats == null) {
            throw new IllegalArgumentException("'stats' must not be null.");
        }

        return new SlaveStats(stats.getAcceptedTasksCount(), stats.getCompletedTasksCount());
    }
}
