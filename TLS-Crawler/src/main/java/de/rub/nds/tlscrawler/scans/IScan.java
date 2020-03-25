/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTarget;

/**
 * Interface to be implemented by scans.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IScan {

    static String SLAVE_INSTANCE_ID = "slaveInstanceId";

    /**
     * @return A unique name.
     */
    String getName();

    /**
     * @param target Target of the scan.
     * @return The scan's result in an IScanResult structure.
     */
    IScanResult scan(IScanTarget target);
}
