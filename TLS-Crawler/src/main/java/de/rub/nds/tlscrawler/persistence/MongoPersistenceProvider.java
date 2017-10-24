/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import com.mongodb.MongoClient;
import de.rub.nds.tlscrawler.data.IScanTask;

import java.util.UUID;

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

    @Override
    public void save(IScanTask task) {
        // TODO
    }

    @Override
    public IScanTask getScanTask(UUID id) {
        // TODO
        return null;
    }
}
