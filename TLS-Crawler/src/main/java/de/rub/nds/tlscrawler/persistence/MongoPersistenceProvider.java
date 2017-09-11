/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import com.mongodb.MongoClient;
import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTask;

/**
 * A persistence provider implementation using MongoDB as
 * the persistence layer.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class MongoPersistenceProvider implements IPersistenceProvider {
    private MongoClient mongo;

    public MongoPersistenceProvider(MongoClient mongo) {
        this.mongo = mongo;
    }

    public void taskCreated(IScanTask task) {
        // Write hollow result structure to db
    }

    public void taskAccepted(IScanTask task) {
        // Write task-accepted timestamp to db
    }

    public void taskStarted(IScanTask task) {
        // write scan-started timestamp to db
    }

    public void save(IScanTask task, IScanResult scanResult) {
        // write scan result to db
    }
}
