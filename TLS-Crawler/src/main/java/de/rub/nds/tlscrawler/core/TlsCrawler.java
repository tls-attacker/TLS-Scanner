/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.scans.IScan;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;

import java.util.Collection;
import java.util.LinkedList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Base class for the crawler modules.
 *
 * @author janis.fliegenschmidt@rub.de
 */
abstract class TlsCrawler implements IScanProvider, IOrganizer {

    private static Logger LOG = LogManager.getLogger();

    private final String instanceId;
    private final IOrchestrationProvider orchestrationProvider;
    private final IPersistenceProvider persistenceProvider;
    protected Collection<IScan> scans;
    protected int port;

    /**
     * TLS-Crawler constructor.
     *
     * @param instanceId The identifier of this instance.
     * @param orchestrationProvider A non-null orchestration provider.
     * @param persistenceProvider A non-null persistence provider.
     * @param scans A neither null nor empty list of available scans.
     */
    public TlsCrawler(String instanceId,
            IOrchestrationProvider orchestrationProvider,
            IPersistenceProvider persistenceProvider,
            Collection<IScan> scans, int port) {
        boolean argumentsInvalid = false;
        this.port = port;
        this.instanceId = instanceId;

        this.orchestrationProvider = orchestrationProvider;
        if (this.orchestrationProvider == null) {
            LOG.error("TLS Crawler was set up with a null Orchestration Provider!");
            argumentsInvalid = true;
        }

        this.persistenceProvider = persistenceProvider;
        if (this.persistenceProvider == null) {
            LOG.error("TLS Crawler was set up with a null Persistence Provider!");
            argumentsInvalid = true;
        }

        this.scans = scans != null ? scans : new LinkedList<>();
        if (this.scans.isEmpty()) {
            LOG.error("TLS Crawler was set up with no scans.");
            argumentsInvalid = true;
        }

        if (argumentsInvalid) {
            throw new IllegalArgumentException("Arguments to TlsCrawler may not be null or empty.");
        }
    }

    @Override
    public Collection<IScan> getScans() {
        return scans;
    }

    public int getPort() {
        return port;
    }

    /**
     * @return The identifier of this instance.
     */
    @Override
    public String getInstanceId() {
        return this.instanceId;
    }

    /**
     * @return The orchestration provider.
     */
    @Override
    public IOrchestrationProvider getOrchestrationProvider() {
        return this.orchestrationProvider;
    }

    /**
     * @return The persistence provider.
     */
    @Override
    public IPersistenceProvider getPersistenceProvider() {
        return this.persistenceProvider;
    }

    /**
     * @param name The name of the scan to return.
     * @return The scan if found, null if no such scan is available.
     */
    @Override
    public IScan getScanByName(String name) {
        for (IScan scan : scans) {
            if (scan.getName().equals(name)) {
                return scan;
            }
        }
        LOG.warn("Scan '{}' could not be found.", name);
        return null;
    }
}
