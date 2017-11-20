/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import de.rub.nds.tlscrawler.data.IPersistenceProviderStats;
import de.rub.nds.tlscrawler.data.IScanTask;
import de.rub.nds.tlscrawler.data.ScanTask;
import org.bson.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Date;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;

import static com.mongodb.client.model.Filters.eq;

/**
 * A persistence provider implementation using MongoDB as
 * the persistence layer.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class MongoPersistenceProvider implements IPersistenceProvider {
    private static Logger LOG = LoggerFactory.getLogger(MongoPersistenceProvider.class);

    private static String COLL_NAME = "scans";

    private MongoClient mongoClient;
    private MongoDatabase database;
    private MongoCollection resultCollection;

    public MongoPersistenceProvider(MongoClientURI mongoUri, String dbName) {
        this.mongoClient = new MongoClient(mongoUri);
        this.database = this.mongoClient.getDatabase(dbName);
        this.resultCollection = this.database.getCollection(COLL_NAME);
    }

    @Override
    public void setUpScanTask(IScanTask newTask) {
        if (newTask.getId() != null) {
            throw new IllegalArgumentException("'newTask' must not have an ID.");
        }

        if (newTask.getResults() != null && !newTask.getResults().isEmpty()) {
            throw new IllegalArgumentException("'results' must be null or empty.");
        }

        Document doc = bsonDocFromScanTask(newTask);

        this.resultCollection.insertOne(doc);
    }

    @Override
    public void save(IScanTask task) {
        // TODO
    }

    @Override
    public IScanTask getScanTask(String id) {
        Document scanTask = (Document)this.resultCollection.find(eq(DBKeys.ID, id)).first();

        return scanTaskFromBsonDoc(scanTask);
    }

    @Override
    public IPersistenceProviderStats getStats() {
        // TODO
        return null;
    }

    static Document bsonDocFromScanTask(IScanTask scanTask) {
        Document result = new Document();

        result.append(DBKeys.CREATED_TIMESTAMP, Date.from(scanTask.getCreatedTimestamp()))
                .append(DBKeys.ACCEPTED_TIMESTAMP, Date.from(scanTask.getAcceptedTimestamp()))
                .append(DBKeys.STARTED_TIMESTAMP, Date.from(scanTask.getStartedTimestamp()))
                .append(DBKeys.COMPLETED_TIMESTAMP, Date.from(scanTask.getCompletedTimestamp()))
                .append(DBKeys.TARGET_IP, scanTask.getTargetIp())
                .append(DBKeys.PORTS, new LinkedList(scanTask.getPorts()))
                .append(DBKeys.SCANS, new LinkedList(scanTask.getScans()))
                .append(DBKeys.RESULTS, null);

        return result;
    }

    static IScanTask scanTaskFromBsonDoc(Document scanTask) {
        Collection<Integer> ports = Arrays.asList((Integer[])scanTask.get(DBKeys.PORTS));
        Collection<String> scans = Arrays.asList((String[])scanTask.get(DBKeys.SCANS));

        ScanTask result = new ScanTask(scanTask.getObjectId(DBKeys.ID).toString(),
                scanTask.getDate(DBKeys.CREATED_TIMESTAMP).toInstant(),
                scanTask.getDate(DBKeys.ACCEPTED_TIMESTAMP).toInstant(),
                scanTask.getDate(DBKeys.STARTED_TIMESTAMP).toInstant(),
                scanTask.getDate(DBKeys.COMPLETED_TIMESTAMP).toInstant(),
                scanTask.getString(DBKeys.TARGET_IP),
                ports,
                scans);

        // TODO Add results.

        return result;
    }

    /**
     * Constants of the keys in the result documents used in MongoDB.
     */
    static class DBKeys {
        static String ID = "_id";
        static String CREATED_TIMESTAMP = "createdTimestamp";
        static String ACCEPTED_TIMESTAMP = "acceptedTimestamp";
        static String STARTED_TIMESTAMP = "startedTimestamp";
        static String COMPLETED_TIMESTAMP = "completedTimestamp";
        static String TARGET_IP = "targetIp";
        static String PORTS = "ports";
        static String SCANS = "scans";
        static String RESULTS = "results";
    }
}
