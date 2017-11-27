/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.ISlaveStats;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.scans.IScan;

import java.util.List;

/**
 * Interface for TLS-Crawler slaves.
 * It may very likely change in the near future as of 27/11/17.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface ITlsCrawlerSlave {

    /**
     * Sets an orchestration provider for this instance to use.
     *
     * @param orchestrationProvider The orchestration provider.
     */
    void setOrchestrationProvider(IOrchestrationProvider orchestrationProvider);

    /**
     * Sets a persistence provider for this instance to use.
     *
     * @param persistenceProvider The persistence provider.
     */
    void setPersistenceProvider(IPersistenceProvider persistenceProvider);

    /**
     * Provides scans to this instance.
     *
     * @param scans The scans.
     */
    void setScans(List<IScan> scans);

    /**
     * Adds a scan to this instance.
     *
     * @param scan The scan.
     */
    void addScan(IScan scan);

    /**
     * Provides information about the work of this slave instance.
     *
     * @return An object implementing the slave stats interface.
     */
    ISlaveStats getStats();
}
