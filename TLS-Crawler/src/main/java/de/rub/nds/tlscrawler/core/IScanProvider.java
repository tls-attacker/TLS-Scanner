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
     * @param name The name of the scan to be retrieved.
     * @return The requested scan.
     */
    IScan getScanByName(String name);

    /**
     * @return A collection of scans that should be executed.
     */
    Collection<IScan> getScans();

    /**
     * @return A collection of ports that should be scanned on.
     */
    int getPort();

}
