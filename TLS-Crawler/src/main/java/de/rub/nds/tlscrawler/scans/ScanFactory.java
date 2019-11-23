/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import java.util.Collection;
import java.util.LinkedList;

/**
 * Factory class to provide scans.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class ScanFactory {
    private static ScanFactory _instance = new ScanFactory();

    /**
     * @return The Singleton's instance.
     */
    public static ScanFactory getInstance() {
        return _instance;
    }

    private ScanFactory() { }

    /**
     * Retruns all scans which are part of the TLS-Crawler project.
     *
     * @return A list of instantiated scans.
     */
    public Collection<IScan> getBuiltInScans() {
        Collection<IScan> result = new LinkedList<>();

        result.add(new FriendlyTlsScan());
        result.add(new NullScan());
        result.add(new PingScan());
        result.add(new TlsScan());

        return result;
    }

    // TODO: Implement Scan PlugIns
}
