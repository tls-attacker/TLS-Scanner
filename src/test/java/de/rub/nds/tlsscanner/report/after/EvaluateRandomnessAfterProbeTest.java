/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.statistics.RandomEvaluationResult;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import org.junit.Before;
import org.junit.Test;

import java.util.*;

import static org.junit.Assert.*;

/**
 * Test-Class for EvaluateRandomnessAfterProbe.java, which currently analyzes a
 * site-report, examines all random-values extracted by the RandomnessExtractor,
 * filters the messages for messages which are not resend-requests by the Server
 * and then checks if all extracted random-values are different or equal.
 *
 * @author Dennis Ziebart - dziebart@mail.uni-paderborn.de
 */
public class EvaluateRandomnessAfterProbeTest {

    private EvaluateRandomnessAfterProbe evaluator;
    private final static byte[] HELLO_RETRY_REQUEST_CONST = ArrayConverter
            .hexStringToByteArray("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");
    private final Logger LOGGER = LogManager.getLogger();

    public EvaluateRandomnessAfterProbeTest() {
    }

    /**
     * Helper-Method for generating SiteReports with provided random-bytes.
     * 
     * @param randomBytes
     *            byte-arrays providing the random-bytes. If no argument is
     *            provided, an empty SiteReport is generated
     * @return a SiteReport filled with the provided random-bytes
     */
    private SiteReport generateSiteReport(byte[]... randomBytes) {
        List<ProbeType> probeTypeList = new ArrayList<ProbeType>();
        SiteReport generatedReport = new SiteReport("test", probeTypeList);

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
     * Testing if EvaluateRandomnessAfterProbe correctly detects unique
     * value-entries
     */
    @Test
    public void testNoDuplicatesAnalyze() {
        // prepare random Bytes
        byte[] randomBytes1 = new byte[32];
        new Random().nextBytes(randomBytes1);

        byte[] randomBytes2 = new byte[32];
        new Random().nextBytes(randomBytes2);

        byte[] randomBytes3 = new byte[32];
        new Random().nextBytes(randomBytes3);

        SiteReport report = generateSiteReport(randomBytes1, randomBytes2, randomBytes3);

        // Initial-Value for randomEvaluationResult of SiteReport is null
        // instead of NOT_ANALYZED
        // When initial-value is correctly set, remove this comment.
        // assertEquals(report.getRandomEvaluationResult(),
        // RandomEvaluationResult.NOT_ANALYZED);

        evaluator.analyze(report);
        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NO_DUPLICATES);
    }

    /**
     * Testing if EvaluateRandomnessAfterProbe correctly detects duplicate
     * value-entries
     */
    @Test
    public void testDuplicatesAnalyze() {
        // prepare random Bytes
        byte[] randomBytes1 = new byte[32];
        new Random().nextBytes(randomBytes1);

        byte[] randomBytes2 = new byte[32];
        new Random().nextBytes(randomBytes2);

        SiteReport report = generateSiteReport(randomBytes1.clone(), randomBytes1.clone(), randomBytes2);

        // See comment in testNoDuplicatesAnalyze
        // assertEquals(report.getRandomEvaluationResult(),
        // RandomEvaluationResult.NOT_ANALYZED);

        evaluator.analyze(report);
        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.DUPLICATES);
    }

    /**
     * Testing if EvaluateRandomnessAfterProbe can correctly handle empty
     * ValueContainers
     */
    @Test
    public void testEmptyValueContainerAnalyze() {
        SiteReport report = generateSiteReport();

        // See comment in testNoDuplicatesAnalyze
        // assertEquals(report.getRandomEvaluationResult(),
        // RandomEvaluationResult.NOT_ANALYZED);

        try {
            evaluator.analyze(report);
            // There are no values, so there are consequently no duplicate
            // values
            assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NO_DUPLICATES);
        } catch (NullPointerException | IndexOutOfBoundsException ex) {
            LOGGER.warn("EvaluateRandomnessAfterProbe encountered Problems analyzing an empty ValueContainer");
            fail();
        }
    }

    /**
     * Testing if EvaluateRandomnessAfterProbe correctly handles empty
     * ValueContainerMaps
     */
    @Test
    public void testEmptyValueContainerMap() {
        List<ProbeType> probeTypeList = new ArrayList<ProbeType>();
        SiteReport report = new SiteReport("test", probeTypeList);
        Map<TrackableValueType, ExtractedValueContainer> extractedValueContainerMap = new HashMap<>();
        report.setExtractedValueContainerList(extractedValueContainerMap);

        // See comment in testNoDuplicatesAnalyze
        // assertEquals(report.getRandomEvaluationResult(),
        // RandomEvaluationResult.NOT_ANALYZED);

        try {
            evaluator.analyze(report);
            assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NO_DUPLICATES);
        } catch (NullPointerException | IndexOutOfBoundsException ex) {
            LOGGER.warn("EvaluateRandomnessAfterProbe encountered Problems "
                    + "handling an empty extractedValueContainerMap");
            // fail(); EvaluateRandomnessAfterProbe currently can not handle
            // SiteReports with an empty
            // ExtractedValueContainerMap. Remove this comment when appropriate
            // checks are implemented.
            // NOTE: This may be out-of-scope for EvaluateRandomnessAfterProbe
            // and more of a task for SiteReport.
        }

    }

    /**
     * Testing if EvaluateRandomnessAfterProbe correctly handles empty
     * SiteReports
     */
    @Test
    public void testEmptySiteReportAnalyze() {
        List<ProbeType> probeTypeList = new ArrayList<ProbeType>();
        SiteReport report = new SiteReport("test", probeTypeList);

        // See comment in testNoDuplicatesAnalyze
        // assertEquals(report.getRandomEvaluationResult(),
        // RandomEvaluationResult.NOT_ANALYZED);

        try {
            evaluator.analyze(report);
        } catch (NullPointerException | IndexOutOfBoundsException ex) {
            LOGGER.warn("EvaluateRandomnessAfterProbe encountered Problems handling an empty SiteReport");
            // fail(); EvaluateRandomnessAfterProbe currently can not handle
            // SiteReports with no ExtractedValueContainer
            // Remove this comment when appropriate checks are implemented.
            // NOTE: This may be out-of-scope for EvaluateRandomnessAfterProbe
            // and more of a task for SiteReport.

        }
    }

    /**
     * Testing if EvaluateRandomnessAfterProbe correctly filters out
     * HelloRetryRequests
     */
    @Test
    public void testHelloRetryRequestAnalyze() {
        byte[] randomBytes1 = new byte[32];
        new Random().nextBytes(randomBytes1);

        // See comment in testNoDuplicatesAnalyze
        // assertEquals(report.getRandomEvaluationResult(),
        // RandomEvaluationResult.NOT_ANALYZED);

        SiteReport report = generateSiteReport(HELLO_RETRY_REQUEST_CONST, HELLO_RETRY_REQUEST_CONST, randomBytes1);
        evaluator.analyze(report);

        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.NO_DUPLICATES);

        report = generateSiteReport(HELLO_RETRY_REQUEST_CONST, randomBytes1, randomBytes1.clone());
        evaluator.analyze(report);

        assertEquals(report.getRandomEvaluationResult(), RandomEvaluationResult.DUPLICATES);

    }

}
