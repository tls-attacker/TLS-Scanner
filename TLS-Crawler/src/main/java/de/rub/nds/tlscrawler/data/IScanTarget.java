/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

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
     * @return The port of the target service.
     */
    int getPort();

    /**
     * @return The hostname of the target, may be null
     */
    String getHostname();
}
