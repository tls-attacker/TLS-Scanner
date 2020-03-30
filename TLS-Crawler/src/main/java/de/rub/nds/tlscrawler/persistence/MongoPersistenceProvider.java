/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import com.mongodb.MongoClient;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import de.rub.nds.tlscrawler.data.*;
import org.bson.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;


/**
 * A persistence provider implementation using MongoDB as the persistence layer.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class MongoPersistenceProvider implements IPersistenceProvider {

    private static Logger LOG = LoggerFactory.getLogger(MongoPersistenceProvider.class);

    private boolean initialized = false;
    private final ServerAddress address;
    private final MongoCredential credentials;
    private MongoClient mongoClient;
    private MongoDatabase database;
    
    private MongoCollection currentCollection;

    public MongoPersistenceProvider(ServerAddress address, MongoCredential credentials) {
        LOG.trace("Constructor()");
        this.address = address;
        this.credentials = credentials;
    }

    /**
     * Initializes the MongoDB persistence provider.
     *
     * @param dbName Name of the database to use.
     */
    public void init(String dbName, String collectionName) {
        LOG.trace(String.format("init() with name '%s'", dbName));

        if (this.credentials != null) {
            this.mongoClient = new MongoClient(this.address, Arrays.asList(this.credentials));
        } else {
            this.mongoClient = new MongoClient(this.address);
        }

        this.database = this.mongoClient.getDatabase(dbName);
        this.currentCollection = this.database.getCollection(collectionName);
        this.initialized = true;
        LOG.info(String.format("MongoDB persistence provider initialized, connected to %s.", address.toString()));
        LOG.info(String.format("Database: %s.", database.getName()));
        LOG.info(String.format("CurrentCollection: %s.", currentCollection.getNamespace().getFullName()));
    }

    /**
     * Convenience method to block method entry in situations where the
     * persistence provider is not initialized.
     */
    private void checkInit() {
        if (!this.initialized) {
            String error = String.format("%s has not been initialized.",
                    MongoPersistenceProvider.class.getName());

            LOG.error(error);
            throw new RuntimeException(error);
        }
    }

    @Override
    public void setUpScanTask(IScanTask newTask) {
        this.checkInit();
        LOG.trace("setUpScanTask()");
        if (newTask.getResult() != null) {
            throw new IllegalArgumentException("'results' must be null or empty.");
        }
        Document doc = bsonDocFromScanTask(newTask);
        this.currentCollection.insertOne(doc);
    }

    @Override
    public void setUpScanTasks(Collection<IScanTask> newTasks) {
        this.checkInit();
        LOG.trace("setUpScanTasks()");
        List<Document> bsonDocs = new LinkedList<>();

        for (IScanTask task : newTasks) {
            if (task.getResult() != null) {
                throw new IllegalArgumentException("'results' must be null or empty.");
            }
            bsonDocs.add(bsonDocFromScanTask(task));
        }
        this.currentCollection.insertMany(bsonDocs);
    }

    @Override
    public IPersistenceProviderStats getStats() {
        this.checkInit();

        LOG.trace("getStats()");

        long totalTasks = this.currentCollection.count();

        Document query = new Document(DBKeys.COMPLETED_TIMESTAMP,
                new Document(DBOperations.NOT_EQUAL, null));
        long completedTasks = this.currentCollection.count(query);

        Document minCompCreated = new Document(DBKeys.ID, null)
                .append("minCompleted", new Document(DBOperations.MIN, String.format("$%s", DBKeys.COMPLETED_TIMESTAMP)))
                .append("minAccpeted", new Document(DBOperations.MIN, String.format("$%s", DBKeys.ACCEPTED_TIMESTAMP)));
        Document group = new Document(DBOperations.GROUP, minCompCreated);
        Document result = (Document) this.currentCollection.aggregate(Arrays.asList(group)).first();

        Date minCompDate = (Date) result.get("minCompleted");
        Instant earliestCompletionTimestamp = minCompDate == null ? null : minCompDate.toInstant();
        Date minCreaDate = (Date) result.get("minCreated");
        Instant earliestCreatedTimestamp = minCreaDate == null ? null : minCreaDate.toInstant();

        return new PersistenceProviderStats(
                totalTasks,
                completedTasks,
                earliestCompletionTimestamp,
                earliestCreatedTimestamp);
    }

    static Document bsonDocFromScanTask(IScanTask scanTask) {
        LOG.trace("bsonDocFromScanTask()");

        if (scanTask == null) {
            return null;
        }

        Document result = new Document(DBKeys.ID, scanTask.getId());

        // These must be available:
        result.append(DBKeys.MASTER_INSTANCE_ID, scanTask.getInstanceId());
        result.append(DBKeys.SCAN_TARGET, scanTask.getScanTarget());
        result.append(DBKeys.RESULTS, scanTask.getResult());

        // These might be null and would throw if they were, so they have to be handled.
        result.append(DBKeys.ACCEPTED_TIMESTAMP,
                scanTask.getAcceptedTimestamp() == null ? null : Date.from(scanTask.getAcceptedTimestamp()));

        result.append(DBKeys.COMPLETED_TIMESTAMP,
                scanTask.getCompletedTimestamp() == null ? null : Date.from(scanTask.getCompletedTimestamp()));

        return result;
    }

    /**
     * Constants of the keys in the result documents used in MongoDB.
     */
    static class DBKeys {

        static String ID = "taskId";
        static String MASTER_INSTANCE_ID = "masterInstanceId";
        static String ACCEPTED_TIMESTAMP = "acceptedTimestamp";
        static String COMPLETED_TIMESTAMP = "completedTimestamp";
        static String SCAN_TARGET = "scanTarget";
        static String PORTS = "ports";
        static String RESULTS = "results";
    }

    /**
     * Constants to use in update-queries.
     */
    static class DBOperations {

        static String EQUALS = "$eq";
        static String EXISTS = "$exists";
        static String GROUP = "$group";
        static String IN = "$in";
        static String MATCH = "$match";
        static String MIN = "$min";
        static String NOT_EQUAL = "$ne";
        static String SET = "$set";
    }
}
