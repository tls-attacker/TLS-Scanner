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
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import de.rub.nds.tlscrawler.data.*;
import de.rub.nds.tlscrawler.utility.ITuple;
import org.bson.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
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
        LOG.trace("Constructor()");
        this.mongoUri = mongoUri;
    }

    /**
     * Initializes the MongoDB persistence provider.
     *
     * @param dbName Name of the database to use.
     */
    public void init(String dbName) {
        LOG.trace(String.format("init() with name '%s'", dbName));

        this.mongoClient = new MongoClient(this.mongoUri);
        this.database = this.mongoClient.getDatabase(dbName);
        this.resultCollection = this.database.getCollection(COLL_NAME);

        this.initialized = true;
        LOG.info(String.format("MongoDB persistence provider initialized, connected to %s.", mongoUri.toString()));
    }

    /**
     * Convenience method to block method entry in situations where the persistence provider is not initialized.
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

        if (newTask.getResults() != null && !newTask.getResults().isEmpty()) {
            throw new IllegalArgumentException("'results' must be null or empty.");
        }

        Document doc = bsonDocFromScanTask(newTask);

        this.resultCollection.insertOne(doc);
    }

    @Override
    public void setUpScanTasks(Collection<IScanTask> newTasks) {
        this.checkInit();

        LOG.trace("setUpScanTasks()");

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

        LOG.trace("updateScanTask()");

        if (task.getId() == null || task.getId().length() == 0) {
            LOG.error("Can't update documents without an ID.");
            throw new RuntimeException("Can't update documents without an ID.");
        }

        Date accTs = task.getAcceptedTimestamp() == null ? null : Date.from(task.getAcceptedTimestamp());
        Date staTs = task.getStartedTimestamp() == null ? null : Date.from(task.getStartedTimestamp());
        Date comTs = task.getCompletedTimestamp() == null ? null : Date.from(task.getCompletedTimestamp());

        Document updateDetails = new Document()
                .append(DBKeys.ACCEPTED_TIMESTAMP, accTs)
                .append(DBKeys.STARTED_TIMESTAMP, staTs)
                .append(DBKeys.COMPLETED_TIMESTAMP, comTs)
                .append(DBKeys.RESULTS, resultStructureToBsonDoc(task.getResults()));

        Document update = new Document(DBOperations.SET, updateDetails);

        this.resultCollection.updateOne(eq(DBKeys.ID, task.getId()), update);
    }

    @Override
    public IScanTask getScanTask(String id) {
        this.checkInit();

        LOG.trace("getScanTask()");

        Document scanTask = (Document) this.resultCollection.find(eq(DBKeys.ID, id)).first();

        return scanTask == null ? null : scanTaskFromBsonDoc(scanTask);
    }

    @Override
    public Map<String, IScanTask> getScanTasks(Collection<String> ids) {
        this.checkInit();

        LOG.trace("getScanTasks()");

        Document query = new Document(DBKeys.ID, new Document(DBOperations.IN, ids));
        FindIterable<Document> results = this.resultCollection.find(query);

        IScanTask task;
        HashMap<String, IScanTask> scanTasks = new HashMap<>();
        for (Document doc : results) {
            task = scanTaskFromBsonDoc(doc);
            scanTasks.put(task.getId(), task);
        }

        return scanTasks;
    }

    @Override
    public IPersistenceProviderStats getStats() {
        this.checkInit();

        LOG.trace("getStats()");

        long totalTasks = this.resultCollection.count();

        Document query = new Document(DBKeys.COMPLETED_TIMESTAMP,
                new Document(DBOperations.NOT_EQUAL, null));
        long completedTasks = this.resultCollection.count(query);

        Document minCompCreated = new Document(DBKeys.ID, null)
                .append("minCompleted", new Document(DBOperations.MIN, String.format("$%s", DBKeys.COMPLETED_TIMESTAMP)))
                .append("minCreated", new Document(DBOperations.MIN, String.format("$%s", DBKeys.CREATED_TIMESTAMP)));
        Document group = new Document(DBOperations.GROUP, minCompCreated);
        Document result = (Document)this.resultCollection.aggregate(Arrays.asList(group)).first();

        Date minCompDate = (Date)result.get("minCompleted");
        Instant earliestCompletionTimestamp = minCompDate == null ? null : minCompDate.toInstant();
        Date minCreaDate = (Date)result.get("minCreated");
        Instant earliestCreatedTimestamp = minCreaDate == null ? null : minCreaDate.toInstant();


        return new PersistenceProviderStats(
                totalTasks,
                completedTasks,
                earliestCompletionTimestamp,
                earliestCreatedTimestamp);
    }

    static Document resultStructureToBsonDoc(Collection<IScanResult> results) {
        LOG.trace("resultStructureToBsonDoc()");

        if (results == null) {
            return null;
        }

        Document result = new Document();

        List<Document> convertedResults = new LinkedList<>();
        for (IScanResult scanResult : results) {
            convertedResults.add(iScanResultToBson(scanResult));
        }

        for (Document doc : convertedResults) {
            String id = (String) doc.get(IScanResult.ID_KEY);

            assert id != null;

            result.append(id, doc);
        }

        return result;
    }

    static Document iScanResultToBson(IScanResult result) {
        LOG.trace("iScanResultToBson()");

        if (result == null) {
            return null;
        }

        Document bson = new Document();

        for (ITuple<String, Object> x : result.getContents()) {
            String key = x.getFirst();
            Object val = x.getSecond();

            assert key != null;

            if (val instanceof IScanResult) {
                bson.append(key, iScanResultToBson((IScanResult) val));
            } else if (val instanceof Instant) {
                bson.append(key, Date.from((Instant)val));
            }
            else
            {
                bson.append(key, val);
            }
        }

        return bson;
    }

    static Document bsonDocFromScanTask(IScanTask scanTask) {
        LOG.trace("bsonDocFromScanTask()");

        if (scanTask == null) {
            return null;
        }

        Document result = new Document(DBKeys.ID, scanTask.getId());

        // These must be available:
        result.append(DBKeys.SCAN_ID, scanTask.getScanId());
        result.append(DBKeys.INSTANCE_ID, scanTask.getSlaveId());
        result.append(DBKeys.CREATED_TIMESTAMP, Date.from(scanTask.getCreatedTimestamp()));
        result.append(DBKeys.TARGET_IP, scanTask.getTargetIp());
        result.append(DBKeys.PORTS, new LinkedList(scanTask.getPorts()));
        result.append(DBKeys.SCANS, new LinkedList(scanTask.getScans()));
        result.append(DBKeys.RESULTS, resultStructureToBsonDoc(scanTask.getResults()));

        // These might be null and would throw if they were, so they have to be handled.
        result.append(DBKeys.ACCEPTED_TIMESTAMP,
                scanTask.getAcceptedTimestamp() == null ? null : Date.from(scanTask.getAcceptedTimestamp()));

        result.append(DBKeys.STARTED_TIMESTAMP,
                scanTask.getStartedTimestamp() == null ? null : Date.from(scanTask.getStartedTimestamp()));

        result.append(DBKeys.COMPLETED_TIMESTAMP,
                scanTask.getCompletedTimestamp() == null ? null : Date.from(scanTask.getCompletedTimestamp()));

        return result;
    }

    static IScanTask scanTaskFromBsonDoc(Document scanTask) {
        LOG.trace("scanTaskFromBsonDoc()");

        if (scanTask == null) {
            return null;
        }

        Collection<Integer> ports = (List<Integer>)scanTask.get(DBKeys.PORTS);
        Collection<String> scans = (List<String>)scanTask.get(DBKeys.SCANS);

        Date created = scanTask.getDate(DBKeys.CREATED_TIMESTAMP);
        Date accepted = scanTask.getDate(DBKeys.ACCEPTED_TIMESTAMP);
        Date started = scanTask.getDate(DBKeys.STARTED_TIMESTAMP);
        Date completed = scanTask.getDate(DBKeys.COMPLETED_TIMESTAMP);

        String instanceId = scanTask.getString(DBKeys.INSTANCE_ID);
        String taskId = scanTask.getString(DBKeys.ID);
        String scanId = scanTask.getString(DBKeys.SCAN_ID);
        String targetIp = scanTask.getString(DBKeys.TARGET_IP);

        ScanTask result = new ScanTask(taskId,
                scanId,
                instanceId,
                created == null ? null : created.toInstant(),
                accepted == null ? null : accepted.toInstant(),
                started == null ? null : started.toInstant(),
                completed == null ? null : completed.toInstant(),
                targetIp,
                ports,
                scans);

        Document results = (Document)scanTask.get(DBKeys.RESULTS);
        if (results != null) {
            results.entrySet().stream()
                    .map(x -> (Document)x.getValue())
                    .map(x -> scanResultFromBsonDoc(x))
                    .forEach(result::addResult);
        }

        return result;
    }

    static IScanResult scanResultFromBsonDoc(Document scanResult) {
        LOG.trace("scanResultFromBsonDoc()");

        if (scanResult == null) {
            return null;
        }

        ScanResult result = new ScanResult();

        String identifier = scanResult.getString(IScanResult.ID_KEY);
        scanResult.remove(IScanResult.ID_KEY);
        result.setResultIdentifier(identifier);

        for (Map.Entry<String, Object> e : scanResult.entrySet()) {
            String key = e.getKey();
            Object value = e.getValue();

            if (value instanceof String) {
                result.addString(key, (String)value);
            } else if (value instanceof Long) {
                result.addLong(key, (Long)value);
            } else if (value instanceof Integer) {
                result.addInteger(key, (Integer)value);
            } else if (value instanceof Double) {
                result.addDouble(key, (Double)value);
            } else if (value instanceof Instant) {
                result.addTimestamp(key, (Instant)value);
            } else if (value instanceof Boolean) {
                result.addBoolean(key, (Boolean)value);
            } else if (value instanceof List) {
                List list = (List)value;
                Object typecheck = list.isEmpty() ? null : list.get(0);

                if (typecheck instanceof String) {
                    result.addStringArray(key, list);
                } if (typecheck instanceof Long) {
                    result.addLongArray(key, list);
                } if (typecheck instanceof Integer) {
                    result.addIntegerArray(key, list);
                } if (typecheck instanceof Double) {
                    result.addDoubleArray(key, list);
                } if (typecheck instanceof Byte) {
                    result.addBinaryData(key, list);
                } else {
                    throw new RuntimeException("Unexpected Type.");
                }
            } else if (value instanceof Document) {
                result.addSubResult(key, scanResultFromBsonDoc((Document)value));
            } else {
                throw new RuntimeException("Unexpected Type.");
            }
        }

        return result;
    }

    /**
     * Constants of the keys in the result documents used in MongoDB.
     */
    static class DBKeys {
        static String ID = "_id";
        static String SCAN_ID = "scanId";
        static String INSTANCE_ID = "instanceId";
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
