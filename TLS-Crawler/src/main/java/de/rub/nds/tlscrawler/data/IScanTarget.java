/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import java.util.Collection;

/**
 * Scan target interface.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IScanTarget {

    /**
     * @return The ip of the target host.
     */
    String getIp();

    /**
     * @return The ports of the target services.
     */
    Collection<Integer> getPorts();
}
