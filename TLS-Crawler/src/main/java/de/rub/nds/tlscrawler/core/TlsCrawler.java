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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Base class for the crawler modules.
 *
 * @author janis.fliegenschmidt@rub.de
 */
class TlsCrawler implements IScanProvider, IOrganizer {
    private static Logger LOG = LoggerFactory.getLogger(TlsCrawler.class);

    private String instanceId;
    private IOrchestrationProvider orchestrationProvider;
    private IPersistenceProvider persistenceProvider;
    private List<IScan> scans;

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
                      List<IScan> scans) {
        boolean argumentsInvalid = false;

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

    /**
     * @return The identifier of this instance.
     */
    public String getInstanceId() {
        return this.instanceId;
    }

    /**
     * @return The orchestration provider.
     */
    public IOrchestrationProvider getOrchestrationProvider() {
        return this.orchestrationProvider;
    }

    /**
     * @return The persistence provider.
     */
    public IPersistenceProvider getPersistenceProvider() {
        return this.persistenceProvider;
    }

    /**
     * @return The list of available scans.
     */
    @Override
    public List<IScan> getScans() {
        return this.scans;
    }

    /**
     * @return A list of names of available scans.
     */
    @Override
    public List<String> getScanNames() {
        return this.scans.stream().map(IScan::getName).collect(Collectors.toList());
    }

    /**
     * @param name The name of the scan to check.
     * @return A boolean indicating whether a scan with the given name is available.
     */
    @Override
    public boolean isScanAvailable(String name) {
        return this.getScanNames().contains(name);
    }

    /**
     * @param name The name of the scan to return.
     * @return The scan if found, null if no such scan is available.
     */
    @Override
    public IScan getScanByName(String name) {
        Optional<IScan> result = this.getScans().stream().filter(x -> x.getName().equals(name)).findAny();

        if (!result.isPresent()) {
            LOG.warn(String.format("Scan '%s' could not be found.", name));
        }

        return result.orElse(null);
    }
}
