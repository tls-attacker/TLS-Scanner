/**
 * TLS Crawler
 * <p>
 * Licensed under Apache 2.0
 * <p>
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;

/**
 * Base class for the crawler modules.
 *
 * @author janis.fliegenschmidt@rub.de
 */
abstract class TlsCrawler implements IScanProvider, IOrganizer {

    private final String instanceId;
    private final IOrchestrationProvider orchestrationProvider;
    private final IPersistenceProvider persistenceProvider;

    /**
     * TLS-Crawler constructor.
     *
     * @param instanceId            The identifier of this instance.
     * @param orchestrationProvider A non-null orchestration provider.
     * @param persistenceProvider   A non-null persistence provider.
     */
    public TlsCrawler(String instanceId,
                      IOrchestrationProvider orchestrationProvider,
                      IPersistenceProvider persistenceProvider) {

        this.instanceId = instanceId;
        this.orchestrationProvider = orchestrationProvider;
        this.persistenceProvider = persistenceProvider;
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
}
