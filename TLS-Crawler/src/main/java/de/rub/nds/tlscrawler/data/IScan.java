/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

/**
 * Scan interface.
 * This interface should be implemented by the individual scans.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IScan {

    /**
     * @return The name of the scan.
     */
    String getName();

    /**
     * @param target The target to scan.
     * @return The scan result.
     */
    IScanResult perform(IScanTarget target);
}
