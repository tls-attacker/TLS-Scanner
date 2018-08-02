/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.scans.IScan;

import java.util.Collection;

/**
 * Interface for objects to be passed to workers to provide them with the
 * necessary scans.
 *
 * @author janis.fliegenschmidt@rub.de
 */
interface IScanProvider {

    /**
     * @return A list of all available scans.
     */
    Collection<IScan> getScans();

    /**
     * @return A list of the names of all the available scans.
     */
    Collection<String> getScanNames();

    /**
     * @param name The name of the scan to check.
     * @return A boolean indicating whether a scan with the given name is available.
     */
    boolean isScanAvailable(String name);

    /**
     * @param name The name of the scan to be retrieved.
     * @return The requested scan.
     */
    IScan getScanByName(String name);
}
