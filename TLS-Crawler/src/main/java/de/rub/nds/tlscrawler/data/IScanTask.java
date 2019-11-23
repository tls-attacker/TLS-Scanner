/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import java.time.Instant;
import java.util.Collection;

/**
 * Scan task interface.
 * Interface to the document that will eventually be persisted.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IScanTask {

    /**
     * @return The id of the scan task.
     */
    String getId();

    /**
     * Returns the name/id of the entire scan, i. e. all individual
     * scan tasks that were scheduled due to a single command share this id.
     *
     * @return The id of the scan.
     */
    String getScanId();

    /**
     * Returns the ID of the master which created the scan task.
     *
     * @return The id of the master instance.
     */
    String getInstanceId();

    /**
     * @return The point in time at which the scan was scheduled.
     */
    Instant getCreatedTimestamp();

    /**
     * @return The point in time a slave accepted this task.
     */
    Instant getAcceptedTimestamp();

    /**
     * @return The point in time a slave started working on the task.
     */
    Instant getStartedTimestamp();

    /**
     * @return The point in time the slave finished working on the task.
     */
    Instant getCompletedTimestamp();

    /**
     * @return The target that should be scanned.
     */
    String getTargetIp();

    /**
     * @return A list of Ports to be scanned.
     */
    Collection<Integer> getPorts();

    /**
     * @return A list of scans to be performed.
     */
    Collection<String> getScans();

    /**
     * @return Returns the scan target.
     */
    IScanTarget getScanTarget();

    /**
     * @return Returns the scan results.
     */
    Collection<IScanResult> getResults();
}
