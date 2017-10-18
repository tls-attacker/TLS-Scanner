/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.IScan;
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
class TLSCrawler {
    private static Logger LOG = LoggerFactory.getLogger(TLSCrawler.class);

    private IOrchestrationProvider orchestrationProvider;
    private IPersistenceProvider persistenceProvider;
    private List<IScan> scans;

    public TLSCrawler(IOrchestrationProvider orchestrationProvider, IPersistenceProvider persistenceProvider, List<IScan> scans) {
        this.orchestrationProvider = orchestrationProvider;
        if (this.orchestrationProvider == null) {
            LOG.error("TLS Crawler was set up with a null Orchestration Provider!");
        }

        this.persistenceProvider = persistenceProvider;
        if (this.persistenceProvider == null) {
            LOG.error("TLS Crawler was set up with a null Persistence Provider!");
        }

        this.scans = scans != null ? scans : new LinkedList<>();
        if (this.scans.isEmpty()) {
            LOG.error("TLS Crawler was set up with no scans.");
        }
    }

    protected IOrchestrationProvider getOrchestrationProvider() {
        return this.orchestrationProvider;
    }

    protected IPersistenceProvider getPersistenceProvider() {
        return this.persistenceProvider;
    }

    protected List<IScan> getScans() {
        return this.scans;
    }

    protected List<String> getScanNames() {
        return this.scans.stream().map(IScan::getName).collect(Collectors.toList());
    }

    protected IScan getScanByName(String name) {
        Optional<IScan> result = this.scans.stream().filter(x -> x.getName().equals(name)).findAny();

        if (!result.isPresent()) {
            LOG.warn(String.format("Scan '%s' could not be found.", name));
        }

        return result.isPresent() ? result.get() : null;
    }
}
