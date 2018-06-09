/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTask;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlscrawler.data.ScanTask;
import de.rub.nds.tlscrawler.utility.ITuple;
import org.bson.Document;
import org.junit.Assert;
import org.junit.Test;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Contains tests for the MongoDB persistence provider.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class MongoPersistenceProviderTest {

    /*
     * REGION: Tests for conversion functions.
     */
    @Test
    public void resultStructureToBsonDoc_SmokeTest() throws Exception {

        // Set up test doc:
        ScanResult result = new ScanResult("testResult");

        result.addString("thisIs", "aTest");
        result.addInteger("hopeToSucceed", 100);
        result.addSubResult("subres", new ScanResult("subres"));

        List<IScanResult> a = new LinkedList<>();
        a.add(result);

        Document testDoc = MongoPersistenceProvider.resultStructureToBsonDoc(a);

        // Set up reference doc
        // CAREFUL: Doubly nested since method accepts a list of results.
        // IScanTask.getResults() yields a list, therefore this should handle one.
        Document referenceDoc = new Document("testResult", new Document()
                .append(IScanResult.ID_KEY, "testResult")
                .append("thisIs", "aTest")
                .append("hopeToSucceed", 100)
                .append("subres", new Document(IScanResult.ID_KEY, "subres")));

        // Convert to string and compare
        String expected = referenceDoc.toString();
        String actual = testDoc.toString();

        Assert.assertEquals(expected, actual);
    }

    @Test
    public void resultStructureToBsonDoc_NullYieldsNull() throws Exception {
        Assert.assertEquals(null, MongoPersistenceProvider.resultStructureToBsonDoc(null));
    }

    @Test
    public void iScanResultToBson_SmokeTest() throws Exception {

        // Set up test doc:
        ScanResult result = new ScanResult("testResult");

        result.addString("thisIs", "aTest");
        result.addInteger("hopeToSucceed", 100);
        result.addSubResult("subres", new ScanResult("subres"));

        Document testDoc = MongoPersistenceProvider.iScanResultToBson(result);

        // Set up reference doc
        // CAREFUL: Not nested since this is a helper method to
        // "resultStructureToBsonDoc" handling the individual items. (see above)
        Document referenceDoc = new Document()
                .append(IScanResult.ID_KEY, "testResult")
                .append("thisIs", "aTest")
                .append("hopeToSucceed", 100)
                .append("subres", new Document(IScanResult.ID_KEY, "subres"));

        // Convert to string and compare
        String expected = referenceDoc.toString();
        String actual = testDoc.toString();

        Assert.assertEquals(expected, actual);
    }

    @Test
    public void iScanResultToBson_NullYieldsNull() throws Exception {
        Assert.assertEquals(null, MongoPersistenceProvider.iScanResultToBson(null));
    }

    @Test
    public void scanTaskFromBsonDoc_SmokeTest() throws Exception {
        Document sct = new Document(MongoPersistenceProvider.DBKeys.ID, "myId")
                .append(MongoPersistenceProvider.DBKeys.PORTS, Arrays.asList(2, 4, 5))
                .append(MongoPersistenceProvider.DBKeys.SCANS, Arrays.asList("Scan1", "Scan2"));

        IScanTask res = MongoPersistenceProvider.scanTaskFromBsonDoc(sct);

        Assert.assertEquals("myId", sct.get(MongoPersistenceProvider.DBKeys.ID));

        Collection<Integer> ports = res.getPorts();
        Assert.assertEquals(3, ports.size());
        Assert.assertTrue(ports.containsAll(Arrays.asList(2, 4, 5)));

        Collection<String> scans = res.getScans();
        Assert.assertEquals(2, scans.size());
        Assert.assertTrue(scans.contains("Scan1"));
        Assert.assertTrue(scans.contains("Scan2"));
    }

    @Test
    public void scanTaskFromBsonDoc_NullYieldsNull() throws Exception {
        Assert.assertEquals(null, MongoPersistenceProvider.scanTaskFromBsonDoc(null));
    }

    @Test
    public void scanResultFromBsonDoc_SmokeTest() throws Exception {
        Instant ts = Instant.now();

        Document doc = new Document(IScanResult.ID_KEY, "myId")
                .append("myInteger", 234)
                .append("myLong", 234L)
                .append("myString", "testString")
                .append("myDouble", 23.4D)
                .append("myTimestamp", ts)
                .append("myBinaryData", Arrays.asList(new Byte[] { 23, 32, 55}));

        IScanResult res = MongoPersistenceProvider.scanResultFromBsonDoc(doc);

        List<ITuple<String, Object>> data = res.getContents();

        List<String> keys = data.stream()
                .map(x -> x.getFirst())
                .collect(Collectors.toList());

        Assert.assertTrue(keys.containsAll(Arrays.asList(
                IScanResult.ID_KEY, "myInteger", "myLong", "myString",
                "myDouble", "myTimestamp", "myBinaryData")));
    }

    @Test
    public void scanResultFromBsonDoc_NullYieldsNull() throws Exception {
        Assert.assertEquals(null, MongoPersistenceProvider.scanResultFromBsonDoc(null));
    }

    @Test
    public void bsonDocFromScanTask_SmokeTest() throws Exception {
        Instant now = Instant.now();
        IScanTask st = new ScanTask(
                "disId",
                "disScanId",
                "disSlaveId",
                now,
                null,
                null,
                null,
                "1.2.3.4",
                Arrays.asList(1, 2, 3, 4),
                Arrays.asList("Scan1"));

        Document doc = MongoPersistenceProvider.bsonDocFromScanTask(st);

        Assert.assertEquals("disId", doc.get(MongoPersistenceProvider.DBKeys.ID));
        Assert.assertEquals(now, ((Date)doc.get(MongoPersistenceProvider.DBKeys.CREATED_TIMESTAMP)).toInstant());

        Collection<Integer> ports = (Collection<Integer>)doc.get(MongoPersistenceProvider.DBKeys.PORTS);
        Assert.assertNotNull(ports);
        Assert.assertTrue(ports.containsAll(Arrays.asList(1, 2, 3, 4)));
    }

    @Test
    public void bsonDocFromScanTask_NullYieldsNull() throws Exception {
        Assert.assertEquals(null, MongoPersistenceProvider.bsonDocFromScanTask(null));
    }
}