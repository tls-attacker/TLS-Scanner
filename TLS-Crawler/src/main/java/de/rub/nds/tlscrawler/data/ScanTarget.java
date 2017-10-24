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
 * Scan target implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class ScanTarget implements IScanTarget {
    private String ip;
    private Collection<Integer> ports;

    public ScanTarget(String ip, Collection<Integer> ports) {
        this.ip = ip;
        this.ports = ports;
    }

    @Override
    public String getIp() {
        return this.ip;
    }

    @Override
    public Collection<Integer> getPorts() {
        return this.ports;
    }
}
