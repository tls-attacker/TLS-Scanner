/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

/**
 * Interface for statistics from a slave process.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface ISlaveStats {

    /**
     * @return The number of accepted tasks.
     */
    long getAcceptedTasksCount();

    /**
     * @return The number of completed tasks.
     */
    long getCompletedTasksCount();
}
