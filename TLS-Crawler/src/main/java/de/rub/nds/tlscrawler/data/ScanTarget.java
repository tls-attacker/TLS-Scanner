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
public class ScanTarget implements Serializable {

    private final String ip;
    private final String hostname;
    private final int port;

    private ScanTarget() {
        ip = null;
        hostname = null;
        port = 0;
    }

    public ScanTarget(String ip, String hostname, int port) {
        this.ip = ip;
        this.hostname = hostname;
        this.port = port;
    }

    public String getIp() {
        return this.ip;
    }

    public int getPort() {
        return this.port;
    }

    public String getHostname() {
        return hostname;
    }
}
