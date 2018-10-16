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
    private final Object _syncroot = new Object();

    private long acceptedTaskCount;
    private long completedTaskCount;

    public SlaveStats(long acceptedTaskCount, long completedTaskCount) {
        this.acceptedTaskCount = acceptedTaskCount;
        this.completedTaskCount = completedTaskCount;
    }

    @Override
    public long getAcceptedTasksCount() {
        long result;

        synchronized (_syncroot) {
            result = this.acceptedTaskCount;
        }

        return result;
    }

    @Override
    public long getCompletedTasksCount() {
        long result;

        synchronized (_syncroot) {
            result = this.completedTaskCount;
        }

        return result;
    }

    public void incrementAcceptedTaskCount(long increment) {
        synchronized (_syncroot) {
            this.acceptedTaskCount += increment;
        }
    }

    public void incrementCompletedTaskCount(long increment) {
        synchronized (_syncroot) {
            this.completedTaskCount += increment;
        }
    }

    @Override
    public String toString() {
        long atc;
        long ctc;

        synchronized (_syncroot) {
            atc = this.acceptedTaskCount;
            ctc = this.completedTaskCount;
        }

        return "### Slave Stats: "
                + atc + "accepted, "
                + ctc + "completed.";
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
