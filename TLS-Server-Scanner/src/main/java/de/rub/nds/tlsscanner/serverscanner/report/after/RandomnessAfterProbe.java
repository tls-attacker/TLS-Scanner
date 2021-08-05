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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsscanner.serverscanner.constants.RandomType;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.EntropyReport;

import java.util.*;

import de.rub.nds.tlsscanner.serverscanner.util.StatisticalTests;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * AfterProbe which analyses the random material extracted using the TLS RNG Probe by employing statistical tests
 * defined by NIST SP 800-22. The test results are then passed onto the SiteReport, displaying them at the end of the
 * scan procedure.
 *
 */
public class RandomnessAfterProbe extends AfterProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    // TLS 1.3 specific message requesting to send a new ClientHello
    private final static byte[] HELLO_RETRY_REQUEST_CONST =
        ArrayConverter.hexStringToByteArray("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    // TLS 1.3 to TLS 1.2 Downgrade prevention
    private final static byte[] TLS_1_3_TO_TLS_1_2_DOWNGRADE_CONST =
        ArrayConverter.hexStringToByteArray("444F574E47524401");

    // TLS 1.3 to TLS 1.1 or lower Downgrade prevention
    private final static byte[] TLS_1_3_TO_TLS_1_1_DOWNGRADE_CONST =
        ArrayConverter.hexStringToByteArray("444F574E47524400");

    // Minimum 32 000 Bytes ~ 1000 ServerHelloRandoms
    private final int MINIMUM_AMOUNT_OF_BYTES = 32000;
    // Standard value for cryptographic applications (see NIST SP 800-22
    // Document)
    private final double MINIMUM_P_VALUE = 0.01;
    private final int MONOBIT_TEST_BLOCK_SIZE = 1;
    private final int FREQUENCY_TEST_BLOCK_SIZE = 128;
    private final int LONGEST_RUN_BLOCK_SIZE = 8;
    private final int TEMPLATE_TEST_BLOCK_SIZE = 9;
    private final int ENTROPY_TEST_BLOCK_SIZE = 10;

    // How much the time is allowed to deviate between two handshakes when
    // viewed using UNIX time prefix
    private final int UNIX_TIME_ALLOWED_DEVIATION = 31556926; // One year

    /**
     * Checks if the Host utilities Unix time or similar counters for Server Randoms.
     *
     * @return TRUE if the all timestamps are within one year of now
     */
    private boolean checkForUnixTime(ExtractedValueContainer<ComparableByteArray> randomContainer) {

        Integer lastUnixTime = null;
        Integer serverUnixTime = null;
        int matchCounter = 0;

        for (ComparableByteArray byteArray : randomContainer.getExtractedValueList()) {

            byte[] serverRandom = byteArray.getArray();
            if (lastUnixTime != null) {
                if (serverRandom != null) {
                    byte[] unixTimeStamp = new byte[4];
                    System.arraycopy(serverRandom, 0, unixTimeStamp, 0, HandshakeByteLength.UNIX_TIME);
                    serverUnixTime = ArrayConverter.bytesToInt(unixTimeStamp);
                    if (serverUnixTime > System.currentTimeMillis() / 1000 + UNIX_TIME_ALLOWED_DEVIATION
                        || serverUnixTime < System.currentTimeMillis() / 1000 - UNIX_TIME_ALLOWED_DEVIATION) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    @Override
    public void analyze(SiteReport report) {

        ExtractedValueContainer<ComparableByteArray> randomExtractedValueContainer =
            report.getExtractedValueContainerMap().get(TrackableValueType.RANDOM);
        ExtractedValueContainer<ComparableByteArray> sessionIdExtractedValueContainer =
            report.getExtractedValueContainerMap().get(TrackableValueType.SESSION_ID);
        ExtractedValueContainer<ComparableByteArray> cbcIvExtractedValueContainer =
            report.getExtractedValueContainerMap().get(TrackableValueType.CBC_IV);
        boolean usesUnixTime = checkForUnixTime(randomExtractedValueContainer);

        List<ComparableByteArray> extractedRandomList =
            filterRandoms(randomExtractedValueContainer.getExtractedValueList(), usesUnixTime);
        List<ComparableByteArray> extractedIvList = cbcIvExtractedValueContainer.getExtractedValueList();
        List<ComparableByteArray> extractedSessionIdList = sessionIdExtractedValueContainer.getExtractedValueList();

        List<EntropyReport> entropyReport = new LinkedList<>();
        entropyReport.add(createEntropyReport(extractedRandomList, RandomType.RANDOM));
        entropyReport.add(createEntropyReport(extractedSessionIdList, RandomType.SESSION_ID));
        entropyReport.add(createEntropyReport(extractedIvList, RandomType.CBC_IV));
        report.putResult(AnalyzedProperty.USES_UNIX_TIMESTAMPS_IN_RANDOM, usesUnixTime);
        report.setEntropyReportList(entropyReport);
    }

    public EntropyReport createEntropyReport(List<ComparableByteArray> byteArrayList, RandomType type) {
        byte[] bytesToAnalyze = convertToSingleByteArray(byteArrayList);
        StatisticalTests.approximateEntropyTest(HELLO_RETRY_REQUEST_CONST, LONGEST_RUN_BLOCK_SIZE);
        boolean duplicates = containsDuplicates(byteArrayList);
        boolean entropyTestPassed =
            StatisticalTests.approximateEntropyTest(bytesToAnalyze, ENTROPY_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE;
        boolean discreteFourierTestPassed = StatisticalTests.discreteFourierTest(bytesToAnalyze) <= MINIMUM_P_VALUE;
        boolean frequencyTestPassed =
            StatisticalTests.frequencyTest(bytesToAnalyze, FREQUENCY_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE;
        boolean longestRunTestPassed =
            StatisticalTests.longestRunWithinBlock(bytesToAnalyze, LONGEST_RUN_BLOCK_SIZE) <= MINIMUM_P_VALUE;
        boolean runsTestPassed = StatisticalTests.runsTest(bytesToAnalyze) <= MINIMUM_P_VALUE;
        boolean monobitTestPassed =
            StatisticalTests.frequencyTest(bytesToAnalyze, MONOBIT_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE;
        double templateTests =
            StatisticalTests.nonOverlappingTemplateTest(bytesToAnalyze, TEMPLATE_TEST_BLOCK_SIZE, MINIMUM_P_VALUE);

        return new EntropyReport(type, byteArrayList.size(), bytesToAnalyze.length, duplicates, frequencyTestPassed,
            monobitTestPassed, runsTestPassed, longestRunTestPassed, discreteFourierTestPassed, entropyTestPassed,
            templateTests);
    }

    private byte[] convertToSingleByteArray(List<ComparableByteArray> byteArrayList) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (ComparableByteArray byteArray : byteArrayList) {
            try {
                outputStream.write(byteArray.getArray());
            } catch (IOException ex) {
                LOGGER.error("Could not write byteArray to outputStream");
            }
        }
        return outputStream.toByteArray();
    }

    private List<ComparableByteArray> filterRandoms(List<ComparableByteArray> extractedValueList,
        boolean usesUnixTime) {
        // Filter usenix Time
        List<ComparableByteArray> filteredList = new LinkedList<>();
        for (ComparableByteArray random : extractedValueList) {
            if (Arrays.equals(random.getArray(), HELLO_RETRY_REQUEST_CONST)) {
                // Remove HELLO RETRY REQUEST "randoms" produced by parsing
                // the Hello Retry Messages as a
                // normal ServerHello message
                filteredList.remove(random);
            } else {
                // There might be a downgrade prevention string in the last 8 bytes of the random, if it is present we
                // remove it
                byte[] lastEightBytes =
                    Arrays.copyOfRange(random.getArray(), HandshakeByteLength.RANDOM - 8, HandshakeByteLength.RANDOM);
                int endIndex;
                int startIndex;
                if (Arrays.equals(lastEightBytes, TLS_1_3_TO_TLS_1_1_DOWNGRADE_CONST)) {
                    endIndex = 24;
                } else if (Arrays.equals(lastEightBytes, TLS_1_3_TO_TLS_1_2_DOWNGRADE_CONST)) {
                    endIndex = 24;
                } else {
                    endIndex = 32;
                }
                if (usesUnixTime) {
                    startIndex = 4;
                } else {
                    startIndex = 0;
                }
                filteredList.add(new ComparableByteArray(Arrays.copyOfRange(random.getArray(), startIndex, endIndex)));
            }
        }
        return filteredList;
    }

    private boolean containsDuplicates(List<ComparableByteArray> byteArrayList) {
        Set<ComparableByteArray> set = new HashSet<>();
        set.addAll(byteArrayList);
        return set.size() != byteArrayList.size();
    }
}
