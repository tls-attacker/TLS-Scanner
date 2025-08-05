/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.afterprobe;

import de.rub.nds.modifiablevariable.util.ComparableByteArray;
import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsscanner.core.constants.RandomType;
import de.rub.nds.tlsscanner.core.report.EntropyReport;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import de.rub.nds.tlsscanner.core.vector.statistics.StatisticalTests;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Abstract AfterProbe implementation that analyzes the randomness quality of various TLS random
 * values including server randoms, session IDs, cookies, and CBC IVs. Performs statistical tests to
 * assess entropy and detects patterns like Unix timestamp usage.
 *
 * @param <ReportT> the type of TLS scan report this probe operates on
 */
public abstract class RandomnessAfterProbe<ReportT extends TlsScanReport>
        extends AfterProbe<ReportT> {

    private static final Logger LOGGER = LogManager.getLogger();

    // TLS 1.3 specific message requesting to send a new ClientHello
    private static final byte[] HELLO_RETRY_REQUEST_CONST =
            DataConverter.hexStringToByteArray(
                    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    // TLS 1.3 to TLS 1.2 Downgrade prevention
    private static final byte[] TLS_1_3_TO_TLS_1_2_DOWNGRADE_CONST =
            DataConverter.hexStringToByteArray("444F574E47524401");

    // TLS 1.3 to TLS 1.1 or lower Downgrade prevention
    private static final byte[] TLS_1_3_TO_TLS_1_1_DOWNGRADE_CONST =
            DataConverter.hexStringToByteArray("444F574E47524400");

    // Standard value for cryptographic applications (see NIST SP 800-22
    // Document)
    private static final double MINIMUM_P_VALUE = 0.01;
    private static final int MONOBIT_TEST_BLOCK_SIZE = 1;
    private static final int FREQUENCY_TEST_BLOCK_SIZE = 128;
    private static final int LONGEST_RUN_BLOCK_SIZE = 8;
    private static final int TEMPLATE_TEST_BLOCK_SIZE = 9;
    private static final int ENTROPY_TEST_BLOCK_SIZE = 10;

    // How much the time is allowed to deviate between two handshakes when
    // viewed using UNIX time prefix
    private static final int UNIX_TIME_ALLOWED_DEVIATION = 31556926; // One year

    /**
     * Checks if the Host utilities Unix time or similar counters for Randoms.
     *
     * @param randomContainer the container with extracted random values to check
     * @return TRUE if all timestamps are within one year of now, FALSE otherwise
     */
    public boolean checkForUnixTime(ExtractedValueContainer<ComparableByteArray> randomContainer) {
        Integer serverUnixTime = null;
        for (ComparableByteArray byteArray : randomContainer.getExtractedValueList()) {
            byte[] serverRandom = byteArray.getArray();
            if (serverRandom != null) {
                byte[] unixTimeStamp = new byte[4];
                System.arraycopy(serverRandom, 0, unixTimeStamp, 0, HandshakeByteLength.UNIX_TIME);
                serverUnixTime = DataConverter.bytesToInt(unixTimeStamp);
                if (serverUnixTime > System.currentTimeMillis() / 1000 + UNIX_TIME_ALLOWED_DEVIATION
                        || serverUnixTime
                                < System.currentTimeMillis() / 1000 - UNIX_TIME_ALLOWED_DEVIATION) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Analyzes various random values extracted from TLS handshakes. Subclasses should implement
     * this method to analyze the specific types of random values relevant to their context (client
     * or server).
     *
     * @param report the TLS scan report containing extracted random value data
     */
    @Override
    public abstract void analyze(ReportT report);

    /**
     * Creates an entropy report for a given list of random byte arrays by performing various
     * statistical tests including frequency tests, runs tests, discrete Fourier tests, and
     * approximate entropy tests.
     *
     * @param byteArrayList the list of random byte arrays to analyze
     * @param type the type of random value being analyzed (RANDOM, SESSION_ID, COOKIE, or CBC_IV)
     * @return an EntropyReport containing the results of all statistical tests
     */
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
        SilentByteArrayOutputStream outputStream = new SilentByteArrayOutputStream();
        for (ComparableByteArray byteArray : byteArrayList) {
            outputStream.write(byteArray.getArray());
        }
        return outputStream.toByteArray();
    }

    /**
     * Filters random values by removing special values like HELLO_RETRY_REQUEST constants and TLS
     * downgrade prevention strings. Also removes Unix timestamps from the beginning of randoms if
     * they are detected to be in use.
     *
     * @param extractedValueList the list of extracted random values to filter
     * @param usesUnixTime whether Unix timestamps are used in the random values
     * @return a filtered list of random values with special values and timestamps removed
     */
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
