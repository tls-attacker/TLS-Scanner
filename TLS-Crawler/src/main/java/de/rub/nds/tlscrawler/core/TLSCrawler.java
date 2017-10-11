/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for the crawler modules.
 *
 * @author janis.fliegenschmidt@rub.de
 */
class TLSCrawler {
    private static Logger LOG = LoggerFactory.getLogger(TLSCrawler.class);

    private IOrchestrationProvider orchestrationProvider;
    private IPersistenceProvider persistenceProvider;

    public TLSCrawler(IOrchestrationProvider orchestrationProvider, IPersistenceProvider persistenceProvider) {
        this.orchestrationProvider = orchestrationProvider;
        if (this.orchestrationProvider == null) {
            LOG.error("TLS Crawler was set up with a null Orchestration Provider!");
        }

        this.persistenceProvider = persistenceProvider;
        if (this.persistenceProvider == null) {
            LOG.error("TLS Crawler was set up with a null Persistence Provider!");
        }
    }

    protected IOrchestrationProvider getOrchestrationProvider() {
        return this.orchestrationProvider;
    }

    protected IPersistenceProvider getPersistenceProvider() {
        return this.persistenceProvider;
    }
}
