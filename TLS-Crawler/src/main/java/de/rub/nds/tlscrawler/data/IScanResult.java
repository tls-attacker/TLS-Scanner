/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import java.time.Instant;
import java.util.List;

/**
 * Scan result interface.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IScanResult {

    // TODO This is still very much a work in progress, as long as not all required fields are decided upon.

    Instant getCreatedTimestamp();
    Instant getStartedTimestamp();
    Instant getCompletedTimestamp();

    List<IScanTask> getScanTasks();

    IScanTarget getScanTarget();

    List<IScanResult> getScanResults();
}
