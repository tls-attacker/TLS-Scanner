/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.utility;

import java.util.Iterator;

/**
 * Produces IPs based on the configured ranges.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IAddressIterator extends Iterator<String> {

    /**
     * Not supported, DO NOT USE.
     * Throws exception.
     */
    @Override
    void remove();
}
