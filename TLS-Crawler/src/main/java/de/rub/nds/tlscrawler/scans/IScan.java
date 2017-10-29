/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlscrawler.data.IScanTarget;
import de.rub.nds.tlscrawler.utility.Tuple;

import java.util.List;

/**
 * Interface to be implemented by scans.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IScan {

    /**
     * @return A unique name.
     */
    String getName();

    /**
     * @param target Target of the scan.
     * @return The scan's result in key-value pairs.
     */
    List<Tuple> scan(IScanTarget target);
}
