/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlscrawler.data.ScanJob;
import de.rub.nds.tlscrawler.orchestration.RabbitMqOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;

/** Interface to be implemented by scans. */
public abstract class Scan implements Runnable {

    protected ScanJob scanJob;

    protected RabbitMqOrchestrationProvider orchestrationProvider;

    protected IPersistenceProvider persistenceProvider;

    protected long rabbitMqAckTag;

    public Scan(
            ScanJob scanJob,
            long rabbitMqAckTag,
            RabbitMqOrchestrationProvider orchestrationProvider,
            IPersistenceProvider persistenceProvider) {
        this.scanJob = scanJob;
        this.rabbitMqAckTag = rabbitMqAckTag;
        this.orchestrationProvider = orchestrationProvider;
        this.persistenceProvider = persistenceProvider;
    }

    public void cancel(boolean timeout) {}

    public ScanJob getScanJob() {
        return this.scanJob;
    }
}
