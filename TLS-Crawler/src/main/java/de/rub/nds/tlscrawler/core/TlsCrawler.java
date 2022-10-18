/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.orchestration.RabbitMqOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;

/**
 * Base class for the crawler modules.
 */
abstract class TlsCrawler {

    protected final RabbitMqOrchestrationProvider orchestrationProvider;
    protected final IPersistenceProvider persistenceProvider;

    public TlsCrawler(RabbitMqOrchestrationProvider orchestrationProvider, IPersistenceProvider persistenceProvider) {
        this.orchestrationProvider = orchestrationProvider;
        this.persistenceProvider = persistenceProvider;
    }

}
