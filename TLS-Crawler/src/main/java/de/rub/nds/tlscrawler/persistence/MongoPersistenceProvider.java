/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
import com.mongodb.lang.NonNull;
import de.rub.nds.tlscrawler.config.delegate.MongoDbDelegate;
import de.rub.nds.tlscrawler.data.BulkScan;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlsscanner.core.converter.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.UuidRepresentation;
import org.mongojack.JacksonMongoCollection;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * A persistence provider implementation using MongoDB as the persistence layer.
 */
public class MongoPersistenceProvider implements IPersistenceProvider {

    private static final Logger LOGGER = LogManager.getLogger();
    private final MongoClient mongoClient;
    private final ObjectMapper mapper;
    private final Map<String, JacksonMongoCollection<ScanResult>> collectionByDbAndCollectionName;
    private JacksonMongoCollection<BulkScan> bulkScanCollection;

    /**
     * Initialize connection to mongodb and setup MongoJack PojoToBson mapper.
     */
    public MongoPersistenceProvider(MongoDbDelegate mongoDbDelegate) {
        ConnectionString connectionString = new ConnectionString("mongodb://" + mongoDbDelegate.getMongoDbHost() + ":" + mongoDbDelegate.getMongoDbPort());
        String pw = "";
        if (mongoDbDelegate.getMongoDbPass() != null) {
            pw = mongoDbDelegate.getMongoDbPass();
        } else if (mongoDbDelegate.getMongoDbPassFile() != null) {
            try {
                pw = Files.readAllLines(Paths.get(mongoDbDelegate.getMongoDbPassFile())).get(0);
            } catch (IOException e) {
                LOGGER.error("Could not read mongoDb password file: ", e);
            }
        }

        MongoCredential credentials = MongoCredential.createCredential(mongoDbDelegate.getMongoDbUser(), mongoDbDelegate.getMongoDbAuthSource(), pw.toCharArray());

        this.mapper = new ObjectMapper();
        LOGGER.trace("Constructor()");
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
        module.addSerializer(new Asn1EncodableSerializer());

        mapper.registerModule(module);
        mapper.registerModule(new JavaTimeModule());
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        mapper.configOverride(BigDecimal.class).setFormat(JsonFormat.Value.forShape(JsonFormat.Shape.STRING));

        MongoClientSettings mongoClientSettings = MongoClientSettings.builder().credential(credentials).applyConnectionString(connectionString).build();
        this.mongoClient = MongoClients.create(mongoClientSettings);

        try {
            this.mongoClient.startSession();
        } catch (Exception e) {
            LOGGER.error("Could not connect to MongoDB: ", e);
            throw new RuntimeException();
        }

        LOGGER.info("MongoDB persistence provider initialized, connected to {}.", connectionString);
    }

    /**
     * On first call creates a collection with the specified name for the specified database and saves it in a hashmap. On
     * repeating calls with same parameters returns the saved collection.
     *
     * @param dbName
     *                       Name of the database to use.
     * @param collectionName
     *                       Name of the collection to create/return
     */
    private JacksonMongoCollection<ScanResult> getCollection(String dbName, String collectionName) {
        if (collectionByDbAndCollectionName.containsKey(dbName + collectionName)) {
            return collectionByDbAndCollectionName.get(dbName + collectionName);
        } else {
            MongoDatabase database = this.mongoClient.getDatabase(dbName);
            LOGGER.info("Init database: {}.", dbName);
            LOGGER.info("Init collection: {}.", collectionName);

            JacksonMongoCollection<ScanResult> collection =
                JacksonMongoCollection.builder().withObjectMapper(mapper).build(database, collectionName, ScanResult.class, UuidRepresentation.STANDARD);
            collectionByDbAndCollectionName.put(dbName + collectionName, collection);

            return collection;
        }
    }

    private JacksonMongoCollection<BulkScan> getBulkScanCollection(String dbName) {
        if (this.bulkScanCollection == null) {
            MongoDatabase database = this.mongoClient.getDatabase(dbName);
            this.bulkScanCollection = JacksonMongoCollection.builder().withObjectMapper(mapper).build(database, "bulkScans", BulkScan.class, UuidRepresentation.STANDARD);
        }
        return this.bulkScanCollection;
    }

    @Override
    public void insertBulkScan(@NonNull BulkScan bulkScan) {
        this.getBulkScanCollection(bulkScan.getName()).insertOne(bulkScan);
    }

    @Override
    public void updateBulkScan(@NonNull BulkScan bulkScan) {
        this.getBulkScanCollection(bulkScan.getName()).removeById(bulkScan.get_id());
        this.insertBulkScan(bulkScan);
    }

    /**
     * Inserts the task into a collection named after the scan and a database named after the workspace of the scan.
     *
     * @param scanResult
     *                   The new scan task.
     */
    @Override
    public void insertScanResult(ScanResult scanResult, String dbName, String collectionName) {
        try {
            if (scanResult != null && scanResult.getResult() != null) {
                LOGGER.info("Writing result for {} into collection: {}", scanResult.getScanTarget().getHostname(), collectionName);
                this.getCollection(dbName, collectionName).insertOne(scanResult);
            }
        } catch (Exception e) {
            // catch JsonMappingException etc.
            LOGGER.error("Exception while writing Result to MongoDB: ", e);
        }

    }

}
