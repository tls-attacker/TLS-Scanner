/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

/**
 * Factory class to provide scans.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class ScanHolder {

    private static ScanHolder _instance = new ScanHolder();

    
    private ScanHolder() {
    }

    public static IScan createScan(String name, int timeout, int parallelThreads, int reexecutions) {
        switch (name) {
            case "tls":
                return new TlsScan(timeout, parallelThreads, reexecutions);
            case "ping":
                return new PingScan();
            case "null":
                return new NullScan();
            default:
                throw new UnsupportedOperationException("Unknown scan");
        }
    }
}
