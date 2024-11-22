/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.afterprobe;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.util.ComparableByteArray;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsscanner.core.constants.RandomType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.core.report.EntropyReport;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import de.rub.nds.tlsscanner.core.vector.statistics.StatisticalTests;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class RandomnessAfterProbe<ReportT extends TlsScanReport>
        extends AfterProbe<ReportT> {

    private static final Logger LOGGER = LogManager.getLogger();

    // TLS 1.3 specific message requesting to send a new ClientHello
    private static final byte[] HELLO_RETRY_REQUEST_CONST =
            ArrayConverter.hexStringToByteArray(
                    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    // TLS 1.3 to TLS 1.2 Downgrade prevention
    private static final byte[] TLS_1_3_TO_TLS_1_2_DOWNGRADE_CONST =
            ArrayConverter.hexStringToByteArray("444F574E47524401");

    // TLS 1.3 to TLS 1.1 or lower Downgrade prevention
    private static final byte[] TLS_1_3_TO_TLS_1_1_DOWNGRADE_CONST =
            ArrayConverter.hexStringToByteArray("444F574E47524400");

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
     * Checks if the Host utilities Unix time or similar counters for Randoms.
     *
     * @return TRUE if the all timestamps are within one year of now
     */
    public boolean checkForUnixTime(ExtractedValueContainer<ComparableByteArray> randomContainer) {
        Integer serverUnixTime = null;
        for (ComparableByteArray byteArray : randomContainer.getExtractedValueList()) {
            byte[] serverRandom = byteArray.getArray();
            if (serverRandom != null) {
                byte[] unixTimeStamp = new byte[4];
                System.arraycopy(serverRandom, 0, unixTimeStamp, 0, HandshakeByteLength.UNIX_TIME);
                serverUnixTime = ArrayConverter.bytesToInt(unixTimeStamp);
                if (serverUnixTime > System.currentTimeMillis() / 1000 + UNIX_TIME_ALLOWED_DEVIATION
                        || serverUnixTime
                                < System.currentTimeMillis() / 1000 - UNIX_TIME_ALLOWED_DEVIATION) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public void analyze(ReportT report) {

        ExtractedValueContainer<ComparableByteArray> cookieExtractedValueContainer =
                report.getExtractedValueContainer(
                        TrackableValueType.COOKIE, ComparableByteArray.class);
        ExtractedValueContainer<ComparableByteArray> randomExtractedValueContainer =
                report.getExtractedValueContainer(
                        TrackableValueType.RANDOM, ComparableByteArray.class);
        ExtractedValueContainer<ComparableByteArray> sessionIdExtractedValueContainer =
                report.getExtractedValueContainer(
                        TrackableValueType.SESSION_ID, ComparableByteArray.class);
        ExtractedValueContainer<ComparableByteArray> cbcIvExtractedValueContainer =
                report.getExtractedValueContainer(
                        TrackableValueType.CBC_IV, ComparableByteArray.class);
        boolean usesUnixTime = checkForUnixTime(randomExtractedValueContainer);

        List<ComparableByteArray> extractedCookieList =
                cookieExtractedValueContainer.getExtractedValueList();
        List<ComparableByteArray> extractedRandomList =
                filterRandoms(randomExtractedValueContainer.getExtractedValueList(), usesUnixTime);
        List<ComparableByteArray> extractedIvList =
                cbcIvExtractedValueContainer.getExtractedValueList();
        List<ComparableByteArray> extractedSessionIdList =
                sessionIdExtractedValueContainer.getExtractedValueList();

        List<EntropyReport> entropyReport = new LinkedList<>();
        entropyReport.add(createEntropyReport(extractedRandomList, RandomType.RANDOM));
        entropyReport.add(createEntropyReport(extractedSessionIdList, RandomType.SESSION_ID));
        entropyReport.add(createEntropyReport(extractedCookieList, RandomType.COOKIE));
        entropyReport.add(createEntropyReport(extractedIvList, RandomType.CBC_IV));
        report.putResult(TlsAnalyzedProperty.USES_UNIX_TIMESTAMPS_IN_RANDOM, usesUnixTime);
        report.putResult(TlsAnalyzedProperty.ENTROPY_REPORTS, entropyReport);
    }

    public EntropyReport createEntropyReport(
            List<ComparableByteArray> byteArrayList, RandomType type) {
        byte[] bytesToAnalyze = convertToSingleByteArray(byteArrayList);
        StatisticalTests.approximateEntropyTest(HELLO_RETRY_REQUEST_CONST, LONGEST_RUN_BLOCK_SIZE);
        int totalDuplicates = getNumberOfDuplicates(byteArrayList);
        boolean duplicates = totalDuplicates > 0;
        String bitString = StatisticalTests.byteArrayToBitString(bytesToAnalyze);
        boolean entropyTestPassed =
                StatisticalTests.approximateEntropyTest(bitString, ENTROPY_TEST_BLOCK_SIZE)
                        <= MINIMUM_P_VALUE;
        boolean discreteFourierTestPassed =
                StatisticalTests.discreteFourierTest(bitString) <= MINIMUM_P_VALUE;
        boolean frequencyTestPassed =
                StatisticalTests.frequencyTest(bitString, FREQUENCY_TEST_BLOCK_SIZE)
                        <= MINIMUM_P_VALUE;
        boolean longestRunTestPassed =
                StatisticalTests.longestRunWithinBlock(bitString, LONGEST_RUN_BLOCK_SIZE)
                        <= MINIMUM_P_VALUE;
        boolean runsTestPassed = StatisticalTests.runsTest(bitString) <= MINIMUM_P_VALUE;
        boolean monobitTestPassed =
                StatisticalTests.frequencyTest(bitString, MONOBIT_TEST_BLOCK_SIZE)
                        <= MINIMUM_P_VALUE;
        double templateTests =
                StatisticalTests.nonOverlappingTemplateTest(
                        bitString, TEMPLATE_TEST_BLOCK_SIZE, MINIMUM_P_VALUE);

        return new EntropyReport(
                type,
                byteArrayList.size(),
                bytesToAnalyze.length,
                duplicates,
                totalDuplicates,
                frequencyTestPassed,
                monobitTestPassed,
                runsTestPassed,
                longestRunTestPassed,
                discreteFourierTestPassed,
                entropyTestPassed,
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

    public List<ComparableByteArray> filterRandoms(
            List<ComparableByteArray> extractedValueList, boolean usesUnixTime) {
        // Filter unix Time
        List<ComparableByteArray> filteredList = new LinkedList<>();
        for (ComparableByteArray random : extractedValueList) {
            if (Arrays.equals(random.getArray(), HELLO_RETRY_REQUEST_CONST)) {
                // Remove HELLO RETRY REQUEST "randoms" produced by parsing
                // the Hello Retry Messages as a
                // normal ServerHello message
                filteredList.remove(random);
            } else {
                // There might be a downgrade prevention string in the last 8 bytes of the random,
                // if it is present we
                // remove it
                byte[] lastEightBytes =
                        Arrays.copyOfRange(
                                random.getArray(),
                                HandshakeByteLength.RANDOM - 8,
                                HandshakeByteLength.RANDOM);
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
                filteredList.add(
                        new ComparableByteArray(
                                Arrays.copyOfRange(random.getArray(), startIndex, endIndex)));
            }
        }
        return filteredList;
    }

    private int getNumberOfDuplicates(List<ComparableByteArray> byteArrayList) {
        Set<ComparableByteArray> set = new HashSet<>();
        set.addAll(byteArrayList);
        return byteArrayList.size() - set.size();
    }
}
