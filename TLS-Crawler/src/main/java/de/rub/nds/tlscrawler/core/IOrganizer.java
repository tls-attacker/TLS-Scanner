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

/**
 * Interface exposing the persistence and orchestration providers.
 *
 * @author janis.fliegenschmidt@rub.de
 */
interface IOrganizer {

    /**
     * @return An orchestration provider.
     */
    IOrchestrationProvider getOrchestrationProvider();

    /**
     * @return A persistence provider.
     */
    IPersistenceProvider getPersistenceProvider();
}
