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
 * Interface for statistics from a master process.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IControllerStats {

    /**
     * @return The total number of tasks in the persistence provider.
     */
    long getTotalTasks();

    /**
     * @return The number of finished tasks in the persistence provider.
     */
    long getFinishedTasks();

    /**
     * @return The earliest timestamp of a completed task.
     */
    Instant getEarliestCompletionTimestamp();

    /**
     * @return The earliest timestamp of a created task.
     */
    Instant getEarliestCreatedTimestamp();
}
