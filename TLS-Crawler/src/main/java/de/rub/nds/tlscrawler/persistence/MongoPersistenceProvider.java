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
import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1Vector;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.crypto.ec.FieldElement;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlscrawler.data.*;
import de.rub.nds.tlscrawler.persistence.converter.Asn1CertificateDeserializer;
import de.rub.nds.tlscrawler.persistence.converter.Asn1CertificateSerializer;
import de.rub.nds.tlscrawler.persistence.converter.ByteArraySerializer;
import de.rub.nds.tlscrawler.persistence.converter.CertificateDeserializer;
import de.rub.nds.tlscrawler.persistence.converter.CertificateSerializer;
import de.rub.nds.tlscrawler.persistence.converter.CustomDhPublicKeySerializer;
import de.rub.nds.tlscrawler.persistence.converter.CustomDsaPublicKeySerializer;
import de.rub.nds.tlscrawler.persistence.converter.CustomEcPublicKeySerializer;
import de.rub.nds.tlscrawler.persistence.converter.CustomRsaPublicKeySerializer;
import de.rub.nds.tlscrawler.persistence.converter.ExtractedValueContainerDeserializer;
import de.rub.nds.tlscrawler.persistence.converter.FieldElementDeserializer;
import de.rub.nds.tlscrawler.persistence.converter.HttpsHeaderDeserializer;
import de.rub.nds.tlscrawler.persistence.converter.HttpsHeaderSerializer;
import de.rub.nds.tlscrawler.persistence.converter.Pkcs1Deserializer;
import de.rub.nds.tlscrawler.persistence.converter.PointDeserializer;
import de.rub.nds.tlscrawler.persistence.converter.PointSerializer;
import de.rub.nds.tlscrawler.persistence.converter.PublicKeyDeserializer;
import de.rub.nds.tlscrawler.persistence.converter.ResponseFingerprintDeserializer;
import de.rub.nds.tlscrawler.persistence.converter.ResponseFingerprintSerializer;
import de.rub.nds.tlscrawler.persistence.converter.VectorDeserializer;
import de.rub.nds.tlscrawler.persistence.converter.VectorSerializer;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.security.PublicKey;
import de.rub.nds.tlsattacker.attacks.general.Vector;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;
import org.bson.BsonDocument;
import org.bson.BsonNull;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.json.simple.JSONObject;
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
        module.addSerializer(new ByteArraySerializer());
        module.addSerializer(new ResponseFingerprintSerializer());
        module.addSerializer(new CertificateSerializer());
        module.addSerializer(new Asn1CertificateSerializer());
        module.addSerializer(new CustomDhPublicKeySerializer());
        module.addSerializer(new CustomEcPublicKeySerializer());
        module.addSerializer(new CustomRsaPublicKeySerializer());
        module.addSerializer(new CustomDsaPublicKeySerializer());
        module.addSerializer(new VectorSerializer());
        module.addSerializer(new PointSerializer());
        module.addSerializer(new HttpsHeaderSerializer());
        module.addDeserializer(ResponseFingerprint.class, new ResponseFingerprintDeserializer());
        module.addDeserializer(HttpsHeader.class, new HttpsHeaderDeserializer());
        module.addDeserializer(FieldElement.class, new FieldElementDeserializer());
        module.addDeserializer(ExtractedValueContainer.class, new ExtractedValueContainerDeserializer());
        module.addDeserializer(Certificate.class, new CertificateDeserializer());
        module.addDeserializer(PublicKey.class, new PublicKeyDeserializer());
        module.addDeserializer(Pkcs1Vector.class, new Pkcs1Deserializer());
        module.addDeserializer(org.bouncycastle.asn1.x509.Certificate.class, new Asn1CertificateDeserializer());
        module.addDeserializer(Point.class, new PointDeserializer());
        module.addDeserializer(Vector.class, new VectorDeserializer());
        //module.addDeserializer(BleichenbacherTestResult.class, new BleichenbacherTestResultDeserializer());
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

    @Override
    public void insertScanTask(ScanTask newTask) {
        this.init(newTask.getScanJob().getScanName(), newTask.getScanJob().getWorkspace());
        LOG.trace("setUpScanTask()");
        this.collection.insertOne(newTask);
    }

    @Override
    public void insertScanTasks(List<ScanTask> newTasks) {
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
                tempTaskList.add(task);
                job = task.getScanJob();
                this.init(job.getScanName(), job.getWorkspace());
            }
        }
        if (!tempTaskList.isEmpty()) {
            this.collection.insertMany(tempTaskList);
        }
    }

    @Override
    public FindIterable<ScanTask> findDocuments(String database, String workspace, Bson findQuery) {
        this.init(database, workspace);
        return collection.find(findQuery);
    }

    @Override
    public Collection<SiteReport> findSiteReports(String database, String workspace, Bson findQuery) {
        this.init(database, workspace);
        List<SiteReport> reportList = new LinkedList<>();
        FindIterable<ScanTask> findIterable = collection.find(findQuery);
        for (ScanTask scanTask : findIterable) {
            Document document = scanTask.getResult();
            LinkedHashMap map = (LinkedHashMap) document.get("report");
            JSONObject obj = new JSONObject(map);
            try {
                SiteReport report = mapper.readValue(obj.toJSONString(), SiteReport.class);
                reportList.add(report);
            } catch (JsonProcessingException ex) {
                LOG.error("Could not deserialize SiteReport", ex);
                ex.printStackTrace();
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
        BsonDocument updateDocument = new BsonDocument("$unset", new BsonDocument("result.report.supportedTls13CipherSuites", new BsonNull()));
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
