/**
 * TLS Crawler
 * <p>
 * Licensed under Apache 2.0
 * <p>
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCredential;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;
import de.rub.nds.tlscrawler.data.IPersistenceProviderStats;
import de.rub.nds.tlscrawler.data.ScanTask;
import de.rub.nds.tlscrawler.persistence.converter.Asn1CertificateSerializer;
import de.rub.nds.tlscrawler.persistence.converter.ByteArraySerializer;
import de.rub.nds.tlscrawler.persistence.converter.CertificateSerializer;
import de.rub.nds.tlscrawler.persistence.converter.CustomDhPublicKeySerializer;
import de.rub.nds.tlscrawler.persistence.converter.CustomDsaPublicKeySerializer;
import de.rub.nds.tlscrawler.persistence.converter.CustomEcPublicKeySerializer;
import de.rub.nds.tlscrawler.persistence.converter.CustomRsaPublicKeySerializer;
import de.rub.nds.tlscrawler.persistence.converter.HttpsHeaderSerializer;
import de.rub.nds.tlscrawler.persistence.converter.PointSerializer;
import de.rub.nds.tlscrawler.persistence.converter.ResponseFingerprintSerializer;
import de.rub.nds.tlscrawler.persistence.converter.VectorSerializer;
import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.log4j.Log4j2;
import org.bson.UuidRepresentation;
import org.mongojack.JacksonMongoCollection;

/**
 * A persistence provider implementation using MongoDB as the persistence layer.
 *
 * @author janis.fliegenschmidt@rub.de
 */
@Log4j2
public class MongoPersistenceProvider implements IPersistenceProvider {

    private final MongoClient mongoClient;
    private final ObjectMapper mapper;
    private final Map<String, JacksonMongoCollection<ScanTask>> collectionByDbAndCollectionName;


    /**
     * Initialize connection to mongodb and setup MongoJack PojoToBson mapper.
     *
     * @param connectionString mongodb server url and port
     * @param credentials      mongodb user name, password and authentication database name
     */
    public MongoPersistenceProvider(ConnectionString connectionString, MongoCredential credentials) {
        this.mapper = new ObjectMapper();
        log.trace("Constructor()");
        this.collectionByDbAndCollectionName = new HashMap<>();

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

        mapper.registerModule(module);
        mapper.registerModule(new JavaTimeModule());
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        mapper.configOverride(BigDecimal.class).setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));

        MongoClientSettings mongoClientSettings = MongoClientSettings.builder().credential(credentials).applyConnectionString(connectionString).build();
        this.mongoClient = MongoClients.create(mongoClientSettings);
        log.info("MongoDB persistence provider initialized, connected to {}.", connectionString.toString());
    }

    /**
     * On first call creates a collection with the specified name for the specified database and saves it in a hashmap.
     * On repeating calls with same parameters returns the saved collection.
     *
     * @param dbName         Name of the database to use.
     * @param collectionName Name of the collection to create/return
     */
    private JacksonMongoCollection<ScanTask> getCollection(String dbName, String collectionName) {
        if (collectionByDbAndCollectionName.containsKey(dbName + collectionName)) {
            return collectionByDbAndCollectionName.get(dbName + collectionName);
        } else {
            log.trace("init() with name '{}'", dbName);

            MongoDatabase database = this.mongoClient.getDatabase(dbName);
            log.info("Database: {}.", dbName);
            log.info("CurrentCollection: {}.", collectionName);

            JacksonMongoCollection<ScanTask> collection = JacksonMongoCollection.builder().withObjectMapper(mapper).build(database, collectionName, ScanTask.class, UuidRepresentation.STANDARD);
            collectionByDbAndCollectionName.put(dbName + collectionName, collection);

            return collection;
        }
    }

    /**
     * Inserts the task into a collection named after the scan and a database named after the workspace of the scan.
     *
     * @param newTask The new scan task.
     */
    @Override
    public void insertScanTask(ScanTask newTask) {
        this.getCollection(newTask.getScanJob().getScanName(), newTask.getScanJob().getWorkspace()).insertOne(newTask);
        log.trace("setUpScanTask()");
    }

    @Override
    public void insertScanTasks(List<ScanTask> newTasks) {
        for (ScanTask task : newTasks) {
            this.insertScanTask(task);
        }
    }


    @Override
    public IPersistenceProviderStats getStats() {
        return null;
    }


}
