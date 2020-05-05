/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.mongodb.MongoClient;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.client.DistinctIterable;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoDatabase;
import de.rub.nds.tlscrawler.data.*;
import de.rub.nds.tlscrawler.persistence.converter.Asn1CertificateSerialisationConverter;
import de.rub.nds.tlscrawler.persistence.converter.ByteArraySerialisationConverter;
import de.rub.nds.tlscrawler.persistence.converter.CertificateSerialisationConverter;
import de.rub.nds.tlscrawler.persistence.converter.CustomDhPublicKeySerialisationConverter;
import de.rub.nds.tlscrawler.persistence.converter.CustomDsaPublicKeySerialisationConverter;
import de.rub.nds.tlscrawler.persistence.converter.CustomEcPublicKeySerialisationConverter;
import de.rub.nds.tlscrawler.persistence.converter.CustomRsaPublicKeySerialisationConverter;
import de.rub.nds.tlscrawler.persistence.converter.HttpsHeaderSerialisationConverter;
import de.rub.nds.tlscrawler.persistence.converter.PointSerialisationConverter;
import de.rub.nds.tlscrawler.persistence.converter.ResponseFingerprintSerialisationConverter;
import de.rub.nds.tlscrawler.persistence.converter.VectorSerialisationConverter;
import de.rub.nds.tlsscanner.report.SiteReport;

import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.BsonDocument;
import org.bson.BsonString;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.mongojack.JacksonMongoCollection;

/**
 * A persistence provider implementation using MongoDB as the persistence layer.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class MongoPersistenceProvider implements IPersistenceProvider {

    private static Logger LOG = LogManager.getLogger();

    private boolean initialized = false;
    private final ServerAddress address;
    private final MongoCredential credentials;
    private MongoClient mongoClient;
    private MongoDatabase database;
    private JacksonMongoCollection<ScanTask> collection;

    private final ObjectMapper mapper;

    private String intializedDb = null;
    private String initalizedWorkspace = null;

    public MongoPersistenceProvider(ServerAddress address, MongoCredential credentials) {
        this.mapper = new ObjectMapper();
        LOG.trace("Constructor()");
        this.address = address;
        this.credentials = credentials;

        SimpleModule module = new SimpleModule();
        module.addSerializer(new ByteArraySerialisationConverter());
        module.addSerializer(new ResponseFingerprintSerialisationConverter());
        module.addSerializer(new CertificateSerialisationConverter());
        module.addSerializer(new Asn1CertificateSerialisationConverter());
        module.addSerializer(new CustomDhPublicKeySerialisationConverter());
        module.addSerializer(new CustomEcPublicKeySerialisationConverter());
        module.addSerializer(new CustomRsaPublicKeySerialisationConverter());
        module.addSerializer(new CustomDsaPublicKeySerialisationConverter());
        module.addSerializer(new VectorSerialisationConverter());
        module.addSerializer(new PointSerialisationConverter());
        module.addSerializer(new HttpsHeaderSerialisationConverter());
        mapper.registerModule(module);
        mapper.registerModule(new JavaTimeModule());
    }

    /**
     * Initializes the MongoDB persistence provider.
     *
     * @param dbName Name of the database to use.
     * @param collectionName
     */
    private void init(String dbName, String collectionName) {
        if (dbName.equals(intializedDb) && collectionName.equals(initalizedWorkspace)) {
            //Connection already initialized
            return;
        }
        LOG.trace("init() with name '{}'", dbName);

        if (this.credentials != null) {
            this.mongoClient = new MongoClient(this.address, Arrays.asList(this.credentials));
        } else {
            this.mongoClient = new MongoClient(this.address);
        }

        this.database = this.mongoClient.getDatabase(dbName);

        collection = JacksonMongoCollection.builder().withObjectMapper(mapper).<ScanTask>build(database, collectionName, ScanTask.class);

        this.initialized = true;
        this.intializedDb = dbName;
        this.initalizedWorkspace = collectionName;
        LOG.info("MongoDB persistence provider initialized, connected to {}.", address.toString());
        LOG.info("Database: {}.", database.getName());
        LOG.info("CurrentCollection: {}.", collectionName);
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
    public void insertScanTask(ScanTask newTask) {
        this.init(newTask.getScanJob().getScanName(), newTask.getScanJob().getWorkspace());
        LOG.trace("setUpScanTask()");
        this.collection.insertOne(newTask);
    }

    @Override
    public void insertScanTasks(List<ScanTask> newTasks) {
        this.checkInit();
        LOG.trace("setUpScanTasks()");
        ScanJob job = null;
        List<ScanTask> tempTaskList = new LinkedList<>();
        for (ScanTask task : newTasks) {
            if (job == null) {
                job = task.getScanJob();
                this.init(job.getScanName(), job.getWorkspace());
            }
            if (task.getScanJob().equals(job)) {
                tempTaskList.add(task);
            } else {
                this.collection.insertMany(tempTaskList);
                tempTaskList = new LinkedList<>();
                job = task.getScanJob();
                this.init(job.getScanName(), job.getWorkspace());
            }
        }
        if (!tempTaskList.isEmpty()) {
            this.collection.insertMany(tempTaskList);
        }
        this.collection.insertMany(newTasks);
    }

    public FindIterable<ScanTask> findDocuments(String database, String workspace, Bson findQuery) {
        this.init(database, workspace);
        return collection.find(findQuery);
    }

    public Collection<SiteReport> findSiteReports(String database, String workspace, Bson findQuery) {
        this.init(database, workspace);
        List<SiteReport> reportList = new LinkedList<>();
        FindIterable<ScanTask> findIterable = collection.find(findQuery);
        for (ScanTask scanTask : findIterable) {
            Document document = scanTask.getResult();
            try {
                SiteReport report = mapper.readValue(document.toJson(), SiteReport.class);
                reportList.add(report);
            } catch (JsonProcessingException ex) {
                LOG.error("Could not deserialize SiteReport", ex);
            }
        }
        return reportList;
    }

    @Override
    public IPersistenceProviderStats getStats() {
        return null;
    }

    @Override
    public long countDocuments(String database, String workspace, Bson query) {
        this.init(database, workspace);
        return collection.countDocuments(query);
    }

    @Override
    public DistinctIterable findDistinctValues(String database, String workspace, String fieldName, Class resultClass) {
        this.init(database, workspace);
        return collection.distinct(fieldName, resultClass);
    }

    @Override
    public void clean(String database, String workspace) {
        this.init(database, workspace);
        BsonDocument updateDocument = new BsonDocument("$unset", new BsonDocument("id", new BsonDocument()));
        collection.updateMany(new BsonDocument(), updateDocument);
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
