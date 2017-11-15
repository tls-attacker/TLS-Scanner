/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import com.mongodb.MongoClient;
import de.rub.nds.tlscrawler.data.IPersistenceProviderStats;
import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTask;
import de.rub.nds.tlscrawler.scans.IScan;

import java.util.Collection;
import java.util.Map;

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
    public void setUpScanTask(IScanTask newTask) {
        // TODO
    }

    @Override
    public void setUpScanTasks(Collection<IScanTask> newTasks) {

    }

    @Override
    public void updateScanTask(IScanTask task) {

    }

    @Override
    public IScanTask getScanTask(String id) {
        // TODO
        return null;
    }

    @Override
    public Map<String, IScanTask> getScanTasks(Collection<String> ids) {
        return null;
    }

    @Override
    public IPersistenceProviderStats getStats() {
        // TODO
        return null;
    }
}
