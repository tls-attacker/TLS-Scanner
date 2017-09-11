/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import java.util.Collection;
import java.util.UUID;

/**
 * Scan task interface.
 * Exposes methods that grant access to data relevant to the
 * individual scan task.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IScanTask {

    /**
     * @return The id of the scan task.
     */
    UUID getId();

    /**
     * @return The target that should be scanned.
     */
    IScanTarget getTarget();

    /**
     * @return A list of scans to be performed.
     */
    Collection<IScan> getScans();
}
