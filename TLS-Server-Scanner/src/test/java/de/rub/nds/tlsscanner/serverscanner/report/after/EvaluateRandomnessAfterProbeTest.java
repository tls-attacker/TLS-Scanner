/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.after;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.statistics.RandomEvaluationResult;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * Test-Class for EvaluateRandomnessAfterProbe.java, which currently analyzes a site-report, examines all random-values
 * extracted by the RandomnessExtractor, filters the messages for messages which are not resend-requests by the Server
 * and then checks if all extracted random-values are different or equal.
 *
 * @author Dennis Ziebart - dziebart@mail.uni-paderborn.de
 */
public class EvaluateRandomnessAfterProbeTest {

    private EvaluateRandomnessAfterProbe evaluator;

    @SuppressWarnings("SpellCheckingInspection")
    private final static byte[] STATIC_RANDOM1 =
        ArrayConverter.hexStringToByteArray("4DDE56987D18EF88F94030A808800DC680BBFD3B9D6B9B522E8339053DC2EDEE");
    private final static byte[] STATIC_RANDOM2 =
        ArrayConverter.hexStringToByteArray("CC4DC97612BDB5DA500D45B69B9F4FD8D1B449AD9FDD509DA7DC95F8077CDA7B");
    private final static byte[] STATIC_RANDOM3 =
        ArrayConverter.hexStringToByteArray("B1BA2D91193EF3448F33B5BEB0D5D31C78A3E5242896B9E539FDE578D2AAB2BC");
    private final static byte[] HELLO_RETRY_REQUEST_CONST =
        ArrayConverter.hexStringToByteArray("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");
    private final Logger LOGGER = LogManager.getLogger();

    public EvaluateRandomnessAfterProbeTest() {
    }

    /**
     * Helper-Method for generating SiteReports with provided random-bytes.
     * 
     * @param  randomBytes
     *                     byte-arrays providing the random-bytes. If no argument is provided, an empty SiteReport is
     *                     generated
     * @return             a SiteReport filled with the provided random-bytes
     */
    private SiteReport generateSiteReport(byte[]... randomBytes) {
        SiteReport generatedReport = new SiteReport("test");

        ExtractedValueContainer extractedValueContainer = new ExtractedValueContainer(TrackableValueType.RANDOM);
        Map<TrackableValueType, ExtractedValueContainer> extractedValueContainerMap = new HashMap<>();

        if (randomBytes.length == 0) {
            // return empty SiteReport
            extractedValueContainerMap.put(TrackableValueType.RANDOM, extractedValueContainer);
            generatedReport.setExtractedValueContainerList(extractedValueContainerMap);
            return generatedReport;
        }

        for (byte[] random : randomBytes) {
            ComparableByteArray generatedRandom = new ComparableByteArray(random);
            extractedValueContainer.put(generatedRandom);
        }

        extractedValueContainerMap.put(TrackableValueType.RANDOM, extractedValueContainer);
        generatedReport.setExtractedValueContainerList(extractedValueContainerMap);

        return generatedReport;
    }

    @Before
    public void setUp() {
        evaluator = new EvaluateRandomnessAfterProbe();
    }

    /**
     * Testing if EvaluateRandomnessAfterProbe correctly detects unique value-entries
     */
    @Test
    public void testNoDuplicatesAnalyze() {
        SiteReport report = generateSiteReport(STATIC_RANDOM1, STATIC_RANDOM2, STATIC_RANDOM3);

        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NOT_ANALYZED);

        evaluator.analyze(report);
        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NO_DUPLICATES);
    }

    /**
     * Testing if EvaluateRandomnessAfterProbe correctly detects duplicate value-entries
     */
    @Test
    public void testDuplicatesAnalyze() {
        SiteReport report = generateSiteReport(STATIC_RANDOM1, STATIC_RANDOM1.clone(), STATIC_RANDOM2);

        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NOT_ANALYZED);

        evaluator.analyze(report);
        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.DUPLICATES);
    }

    /**
     * Testing if EvaluateRandomnessAfterProbe can correctly handle empty ValueContainers
     */
    @Test
    public void testEmptyValueContainerAnalyze() {
        SiteReport report = generateSiteReport();

        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NOT_ANALYZED);
        assertTrue(
            report.getExtractedValueContainerMap().get(TrackableValueType.RANDOM).getExtractedValueList().isEmpty());

        evaluator.analyze(report);

        // If there are no extracted values, there are consecutively no
        // duplicates
        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NO_DUPLICATES);
    }

    /**
     * Testing if EvaluateRandomnessAfterProbe correctly handles empty ValueContainerMaps
     */
    @Test
    public void testEmptyValueContainerMap() {
        SiteReport report = new SiteReport("test");
        Map<TrackableValueType, ExtractedValueContainer> extractedValueContainerMap = new HashMap<>();
        report.setExtractedValueContainerList(extractedValueContainerMap);

        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NOT_ANALYZED);
        assertTrue(report.getExtractedValueContainerMap().isEmpty());

        evaluator.analyze(report);
        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NO_DUPLICATES);
    }

    /**
     * Testing if EvaluateRandomnessAfterProbe correctly handles empty SiteReports
     */
    @Test
    public void testEmptySiteReportAnalyze() {
        SiteReport report = new SiteReport("test");

        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NOT_ANALYZED);
        assertTrue(report.getExtractedValueContainerMap().isEmpty());

        evaluator.analyze(report);
        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NO_DUPLICATES);
    }

    /**
     * Testing if EvaluateRandomnessAfterProbe correctly filters out HelloRetryRequests
     */
    @Test
    public void testHelloRetryRequestAnalyze() {
        SiteReport report = generateSiteReport(HELLO_RETRY_REQUEST_CONST, HELLO_RETRY_REQUEST_CONST, STATIC_RANDOM1);
        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NOT_ANALYZED);

        evaluator.analyze(report);
        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NO_DUPLICATES);

        report = generateSiteReport(HELLO_RETRY_REQUEST_CONST, STATIC_RANDOM1, STATIC_RANDOM1.clone());
        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NOT_ANALYZED);
        evaluator.analyze(report);

        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.DUPLICATES);
    }

}
