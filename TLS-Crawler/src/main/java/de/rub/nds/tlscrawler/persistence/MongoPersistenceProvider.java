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
import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTask;
import de.rub.nds.tlscrawler.data.ScanTask;
import de.rub.nds.tlscrawler.utility.ITuple;
import org.bson.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

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

    private boolean initialized = false;
    private MongoClientURI mongoUri;
    private MongoClient mongoClient;
    private MongoDatabase database;
    private MongoCollection resultCollection;

    public MongoPersistenceProvider(MongoClientURI mongoUri) {
        this.mongoUri = mongoUri;
    }

    public void init(String dbName) {
        this.mongoClient = new MongoClient(this.mongoUri);
        this.database = this.mongoClient.getDatabase(dbName);
        this.resultCollection = this.database.getCollection(COLL_NAME);

        this.initialized = true;
        LOG.info(String.format("MongoDB persistence provider initialized, connected to %s.", mongoUri.toString()));
    }

    @Override
    public void setUpScanTask(IScanTask newTask) {
        this.checkInit();

        if (newTask.getResults() != null && !newTask.getResults().isEmpty()) {
            throw new IllegalArgumentException("'results' must be null or empty.");
        }

        Document doc = bsonDocFromScanTask(newTask);

        this.resultCollection.insertOne(doc);
    }

    @Override
    public void setUpScanTasks(Collection<IScanTask> newTasks) {
        this.checkInit();

        List<Document> bsonDocs = new LinkedList<>();

        for (IScanTask task : newTasks) {
            if (task.getResults() != null && !task.getResults().isEmpty()) {
                throw new IllegalArgumentException("'results' must be null or empty.");
            }

            bsonDocs.add(bsonDocFromScanTask(task));
        }

        this.resultCollection.insertMany(bsonDocs);
    }

    @Override
    public void updateScanTask(IScanTask task) {
        this.checkInit();

        if (task.getId() == null || task.getId().length() == 0) {
            LOG.error("Can't update documents without an ID.");
            throw new RuntimeException("Can't update documents without an ID.");
        }
        Document updateDetails = new Document()
                .append(DBKeys.ACCEPTED_TIMESTAMP, task.getAcceptedTimestamp())
                .append(DBKeys.STARTED_TIMESTAMP, task.getStartedTimestamp())
                .append(DBKeys.COMPLETED_TIMESTAMP, task.getCompletedTimestamp())
                .append(DBKeys.RESULTS, resultStructureToBsonDoc(task.getResults()));

        Document update = new Document(DBOperations.SET, updateDetails);

        this.resultCollection.updateOne(eq(DBKeys.ID, task.getId()), update);
    }

    @Override
    public IScanTask getScanTask(String id) {
        this.checkInit();

        Document scanTask = (Document)this.resultCollection.find(eq(DBKeys.ID, id)).first();

        return scanTaskFromBsonDoc(scanTask);
    }

    @Override
    public Map<String, IScanTask> getScanTasks(Collection<String> ids) {
        // TODO
        return null;
    }

    @Override
    public IPersistenceProviderStats getStats() {
        // TODO
        return null;
    }

    private void checkInit() {
        if (!this.initialized) {
            String error = String.format("%s has not been initialized.",
                    MongoPersistenceProvider.class.getName());

            LOG.error(error);
            throw new RuntimeException(error);
        }
    }

    static Document resultStructureToBsonDoc(Collection<IScanResult> results) {
        Document result = new Document();

        List<Document> convertedResults = new LinkedList<>();
        for (IScanResult scanResult : results) {
            convertedResults.add(iScanResultToBson(scanResult));
        }

        for (Document doc : convertedResults) {
            result.append((String)doc.get(DBKeys.ID), doc);
        }

        return result;
    }

    static Document iScanResultToBson(IScanResult result) {
        Document bson = new Document();

        for (ITuple<String, Object> x : result.getContents()) {
            String key = x.getFirst();
            Object val = x.getSecond();

            if (val instanceof IScanResult) {
                bson.append(key, iScanResultToBson((IScanResult) val));
            } else {
                bson.append(key, val);
            }
        }

        return bson;
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

    /**
     * Constants to use in update-queries.
     */
    static class DBOperations {
        static String SET = "$set";
    }
}
