/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.data;

import java.io.Serializable;

/**
 * Scan target implementation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class ScanTarget implements IScanTarget, Serializable {

    private final String ip;
    private final int port;

    public ScanTarget(String ip, int port) {
        this.ip = ip;
        this.port = port;
    }

    @Override
    public String getIp() {
        return this.ip;
    }

    @Override
    public int getPort() {
        return this.port;
    }
}
