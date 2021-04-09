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
import de.rub.nds.tlsscanner.serverscanner.constants.RandomType;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.constants.RngConstants;

import java.util.*;

import de.rub.nds.tlsscanner.serverscanner.report.result.statistics.RandomMinimalLengthResult;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


import static de.rub.nds.tlsscanner.serverscanner.util.StatisticalTests.*;
import static java.lang.Math.*;

/**
 * AfterProbe which analyses the random material extracted using the TLS RNG Probe by employing statistical tests
 * defined by NIST SP 800-22. The test results are then passed onto the SiteReport, displaying them at the end of the
 * scan procedure.
 * 
 * @author Dennis Ziebart - dziebart@mail.uni-paderborn.de
 */
public class TlsRngAfterProbe extends AfterProbe {

    private static final Logger LOGGER = LogManager.getLogger();
    // For differentiating the test_result using Fischer's method and the
    // percentage of failed templates of the
    // Template test
    
    // TLS 1.3 specific message requesting to send a new ClientHello
    private final static byte[] HELLO_RETRY_REQUEST_CONST =
            ArrayConverter.hexStringToByteArray("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

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


    @Override
    public void analyze(SiteReport report) {

        LOGGER.debug("TLS-RNG-PROBE RESULT : " + report.getResult(AnalyzedProperty.RNG_EXTRACTED));
        if (report.getResult(AnalyzedProperty.RNG_EXTRACTED) == TestResult.FALSE
            || report.getResult(AnalyzedProperty.RNG_EXTRACTED) == TestResult.COULD_NOT_TEST
            || report.getResult(AnalyzedProperty.RNG_EXTRACTED) == TestResult.NOT_TESTED_YET) {
            LOGGER.debug("AfterProbe can only be executed when TlsRngProbe was successfully executed.");
            return;
        }

        List<ComparableByteArray> extractedRandomList = report.getExtractedRandomList();
        List<ComparableByteArray> extractedIVList = report.getExtractedIVList();
        List<ComparableByteArray> extractedSessionIdList = report.getExtractedSessionIDList();

        // Check for HELLO_RETRY_REQUEST_CONSTANT when TLS 1.3
        if (report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.TRUE) {
            for (ComparableByteArray random : extractedRandomList) {
                if (random.equals(HELLO_RETRY_REQUEST_CONST)) {
                    // Remove HELLO RETRY REQUEST "randoms" produced by parsing
                    // the Hello Retry Messages as a
                    // normal ServerHello message
                    extractedRandomList.remove(random);
                }
            }
        }

        List<Byte> fullByteSequence = new ArrayList();

        int serverRandomCounter = 0;
        int sessionIdCounter = 0;
        int iVCounter = 0;

        // Counting extracted Random-Types and building complete Sequence
        // consisting of
        // (ServerHello randoms + SessionIDs) || IVs

        for (int i = 0; i < max(extractedRandomList.size(), extractedSessionIdList.size()); i++) {
            if (i < extractedRandomList.size()) {
                byte[] extractedRandomBytes = extractedRandomList.get(i).getArray();
                serverRandomCounter += extractedRandomBytes.length;
                for (byte b : extractedRandomBytes) {
                    fullByteSequence.add(b);
                }
            }

            if (i < extractedSessionIdList.size()) {
                byte[] extractedSessionIdBytes = extractedSessionIdList.get(i).getArray();
                sessionIdCounter += extractedSessionIdBytes.length;
                for (byte b : extractedSessionIdBytes) {
                    fullByteSequence.add(b);
                }
            }
        }

        for (ComparableByteArray iVector : extractedIVList) {
            byte[] extractedIVBytes = iVector.getArray();
            iVCounter += extractedIVBytes.length;
            for (byte b : extractedIVBytes) {
                fullByteSequence.add(b);
            }
        }

        LOGGER.debug("Number of collected Bytes: " + fullByteSequence.size());
        LOGGER.debug("Consisting of serverRandom: " + serverRandomCounter + " bytes.");
        LOGGER.debug("Consisting of sessionID: " + sessionIdCounter + " bytes.");
        LOGGER.debug("Consisting of IV: " + iVCounter + " bytes.");

        if (serverRandomCounter + sessionIdCounter + iVCounter == 0) {
            LOGGER.debug("No Randomness extracted. Aborting Tests.");
            return;
        }

        if (fullByteSequence.size() < MINIMUM_AMOUNT_OF_BYTES) {
            LOGGER.debug("Minimum Amount of Bytes not reached! This will negatively impact the "
                + "performance of the tests. This will be noted in the site report.");
            report.setRandomMinimalLengthResult(RandomMinimalLengthResult.NOT_FULFILLED);
        } else {
            report.setRandomMinimalLengthResult(RandomMinimalLengthResult.FULFILLED);
        }

        Byte[] fullByteSequenceArrayTmp = new Byte[fullByteSequence.size()];
        fullByteSequenceArrayTmp = fullByteSequence.toArray(fullByteSequenceArrayTmp);
        byte[] fullByteSequenceArray = ArrayUtils.toPrimitive(fullByteSequenceArrayTmp);
        ComparableByteArray testSequenceElement = new ComparableByteArray(fullByteSequenceArray);
        ComparableByteArray[] testSequence = new ComparableByteArray[] { testSequenceElement };
        LinkedList<RandomType> duplicateList = new LinkedList<>();
        LinkedList<RandomType> monoBitList = new LinkedList<>();
        LinkedList<RandomType> frequencyList = new LinkedList<>();
        LinkedList<RandomType> runsList = new LinkedList<>();
        LinkedList<RandomType> longestRunBlockList = new LinkedList<>();
        LinkedList<RandomType> fourierList = new LinkedList<>();
        Map<RandomType, Double> nonOverlappingTemplatePercentagesMap = new HashMap<>();
        LinkedList<RandomType> nonOverlappingTemplateList = new LinkedList<>();
        LinkedList<RandomType> entropyList = new LinkedList<>();
        // Deactivated due to performance hit - May be activated again in the
        // future
        // LinkedList<RandomType> serialList = new LinkedList<>();
        // LinkedList<RandomType> cuSumList = new LinkedList<>();
        // LinkedList<RandomType> cuSumReverseList = new LinkedList<>();

        ComparableByteArray[] extractedRandomArray = new ComparableByteArray[extractedRandomList.size()];
        extractedRandomArray = extractedRandomList.toArray(extractedRandomArray);

        ComparableByteArray[] extractedSessionIdArray = new ComparableByteArray[extractedSessionIdList.size()];
        extractedSessionIdArray = extractedSessionIdList.toArray(extractedSessionIdArray);

        ComparableByteArray[] extractedIvArray = new ComparableByteArray[extractedIVList.size()];
        extractedIvArray = extractedIVList.toArray(extractedIvArray);

        LOGGER.debug("============================================================================================");
        boolean randomDuplicate = testForDuplicates(extractedRandomArray);
        if (randomDuplicate) {
            duplicateList.add(RandomType.RANDOM);
        }
        LOGGER.debug("Duplicates in server Randoms: " + randomDuplicate);
        LOGGER.debug("============================================================================================");
        boolean sessionIdDuplicate = testForDuplicates(extractedSessionIdArray);
        if (sessionIdDuplicate) {
            duplicateList.add(RandomType.SESSION_ID);
        }
        LOGGER.debug("Duplicates in Session IDs : " + sessionIdDuplicate);
        LOGGER.debug("============================================================================================");
        boolean iVDuplicate = testForDuplicates(extractedIvArray);
        if (iVDuplicate) {
            duplicateList.add(RandomType.IV);
        }
        LOGGER.debug("Duplicates in IVs: " + iVDuplicate);
        // /////////////////////////////////////////////////
        report.putRandomDuplicatesResult(duplicateList);
        // ////////////////////////////////////////////////
        LOGGER.debug("============================================================================================");

        if (frequencyTest(extractedRandomArray, MONOBIT_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("MONOBIT_TEST ServerHelloRandom : FAILED");
            monoBitList.add(RandomType.RANDOM);
        } else {
            LOGGER.debug("MONOBIT_TEST ServerHelloRandom : PASSED");
        }
        if (!(extractedSessionIdArray.length == 0)
            && frequencyTest(extractedSessionIdArray, MONOBIT_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("MONOBIT_TEST SessionID : FAILED");
            monoBitList.add(RandomType.SESSION_ID);
        } else {
            LOGGER.debug("MONOBIT_TEST SessionID : PASSED");
        }
        if (!(extractedIvArray.length == 0)
            && frequencyTest(extractedIvArray, MONOBIT_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("MONOBIT_TEST IV : FAILED");
            monoBitList.add(RandomType.IV);
        } else {
            LOGGER.debug("MONOBIT_TEST IV : PASSED");
        }
        if (frequencyTest(testSequence, MONOBIT_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("MONOBIT_TEST FullSequence : FAILED");
            monoBitList.add(RandomType.COMPLETE_SEQUENCE);
        } else {
            LOGGER.debug("MONOBIT_TEST FullSequence : PASSED");
        }
        // /////////////////////////////////////////////////
        report.putMonoBitResult(monoBitList);
        // ////////////////////////////////////////////////
        LOGGER.debug("============================================================================================");

        if (frequencyTest(extractedRandomArray, FREQUENCY_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("FREQUENCY_TEST ServerHelloRandom : FAILED");
            frequencyList.add(RandomType.RANDOM);
        } else {
            LOGGER.debug("FREQUENCY_TEST ServerHelloRandom : PASSED");
        }
        if (!(extractedSessionIdArray.length == 0)
            && frequencyTest(extractedSessionIdArray, FREQUENCY_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("FREQUENCY_TEST SessionID : FAILED");
            frequencyList.add(RandomType.SESSION_ID);
        } else {
            LOGGER.debug("FREQUENCY_TEST SessionID : PASSED");
        }
        if (!(extractedIvArray.length == 0)
            && frequencyTest(extractedIvArray, FREQUENCY_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("FREQUENCY_TEST IV : FAILED");
            frequencyList.add(RandomType.IV);
        } else {
            LOGGER.debug("FREQUENCY_TEST IV : PASSED");
        }
        if (frequencyTest(testSequence, FREQUENCY_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("FREQUENCY_TEST FullSequence : FAILED");
            frequencyList.add(RandomType.COMPLETE_SEQUENCE);
        } else {
            LOGGER.debug("FREQUENCY_TEST FullSequence : PASSED");
        }
        // /////////////////////////////////////////////////
        report.putFrequencyResult(frequencyList);
        // ////////////////////////////////////////////////
        LOGGER.debug("============================================================================================");

        if (runsTest(extractedRandomArray) <= MINIMUM_P_VALUE) {
            LOGGER.debug("RUNS_TEST ServerHelloRandom : FAILED");
            runsList.add(RandomType.RANDOM);
        } else {
            LOGGER.debug("RUNS_TEST ServerHelloRandom : PASSED");
        }
        if (!(extractedSessionIdArray.length == 0) && runsTest(extractedSessionIdArray) <= MINIMUM_P_VALUE) {
            LOGGER.debug("RUNS_TEST SessionID : FAILED");
            runsList.add(RandomType.SESSION_ID);
        } else {
            LOGGER.debug("RUNS_TEST SessionID : PASSED");
        }
        if (!(extractedIvArray.length == 0) && runsTest(extractedIvArray) <= MINIMUM_P_VALUE) {
            LOGGER.debug("RUNS_TEST IV : FAILED");
            runsList.add(RandomType.IV);
        } else {
            LOGGER.debug("RUNS_TEST IV : PASSED");
        }
        if (runsTest(testSequence) <= MINIMUM_P_VALUE) {
            LOGGER.debug("RUNS_TEST FullSequence : FAILED");
            runsList.add(RandomType.COMPLETE_SEQUENCE);
        } else {
            LOGGER.debug("RUNS_TEST FullSequence : PASSED");
        }
        // /////////////////////////////////////////////////
        report.putRunsResult(runsList);
        // ////////////////////////////////////////////////
        LOGGER.debug("============================================================================================");

        if (longestRunWithinBlock(extractedRandomArray, LONGEST_RUN_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("LONGEST_RUN_TEST ServerHelloRandom : FAILED");
            longestRunBlockList.add(RandomType.RANDOM);
        } else {
            LOGGER.debug("LONGEST_RUN_TEST ServerHelloRandom : PASSED");
        }
        if (!(extractedSessionIdArray.length == 0)
            && longestRunWithinBlock(extractedSessionIdArray, LONGEST_RUN_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("LONGEST_RUN_TEST SessionID : FAILED");
            longestRunBlockList.add(RandomType.SESSION_ID);
        } else {
            LOGGER.debug("LONGEST_RUN_TEST SessionID : PASSED");
        }
        if (!(extractedIvArray.length == 0)
            && longestRunWithinBlock(extractedIvArray, LONGEST_RUN_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("LONGEST_RUN_TEST IV : FAILED");
            longestRunBlockList.add(RandomType.IV);
        } else {
            LOGGER.debug("LONGEST_RUN_TEST IV : PASSED");
        }
        if (longestRunWithinBlock(testSequence, LONGEST_RUN_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("LONGEST_RUN_TEST FullSequence : FAILED");
            longestRunBlockList.add(RandomType.COMPLETE_SEQUENCE);
        } else {
            LOGGER.debug("LONGEST_RUN_TEST FullSequence : PASSED");
        }
        // /////////////////////////////////////////////////
        report.putLongestRunBlockResult(longestRunBlockList);
        // ////////////////////////////////////////////////
        LOGGER.debug("============================================================================================");

        if (discreteFourierTest(extractedRandomArray) <= MINIMUM_P_VALUE) {
            LOGGER.debug("FOURIER_TEST ServerHelloRandom : FAILED");
            fourierList.add(RandomType.RANDOM);
        } else {
            LOGGER.debug("FOURIER_TEST ServerHelloRandom : PASSED");
        }
        if (!(extractedSessionIdArray.length == 0) && discreteFourierTest(extractedSessionIdArray) <= MINIMUM_P_VALUE) {
            LOGGER.debug("FOURIER_TEST SessionID : FAILED");
            fourierList.add(RandomType.SESSION_ID);
        } else {
            LOGGER.debug("FOURIER_TEST SessionID : PASSED");
        }
        if (!(extractedIvArray.length == 0) && discreteFourierTest(extractedIvArray) <= MINIMUM_P_VALUE) {
            LOGGER.debug("FOURIER_TEST IV : FAILED");
            fourierList.add(RandomType.IV);
        } else {
            LOGGER.debug("FOURIER_TEST IV : PASSED");
        }
        if (discreteFourierTest(testSequence) <= MINIMUM_P_VALUE) {
            LOGGER.debug("FOURIER_TEST FullSequence : FAILED");
            fourierList.add(RandomType.COMPLETE_SEQUENCE);
        } else {
            LOGGER.debug("FOURIER_TEST FullSequence : PASSED");
        }
        // /////////////////////////////////////////////////
        report.putFourierResult(fourierList);
        // ////////////////////////////////////////////////
        LOGGER.debug("============================================================================================");

        Map<RngConstants.TEMPLATE_CONSTANTS, Double> templateResult;
        double templateFailedPercentage;

        templateResult = nonOverlappingTemplateTest(extractedRandomArray, TEMPLATE_TEST_BLOCK_SIZE, MINIMUM_P_VALUE);
        if (templateResult.get(RngConstants.TEMPLATE_CONSTANTS.TEST_RESULT) == 0) {
            LOGGER.debug("TEMPLATE_TEST ServerHelloRandom : FAILED");
            nonOverlappingTemplateList.add(RandomType.RANDOM);
        } else {
            LOGGER.debug("TEMPLATE_TEST ServerHelloRandom : PASSED");
        }
        templateFailedPercentage = templateResult.get(RngConstants.TEMPLATE_CONSTANTS.PERCENTAGE);
        LOGGER.debug("TEMPLATE_TEST ServerHelloRandom Failed Test Percentage : " + (templateFailedPercentage * 100));
        nonOverlappingTemplatePercentagesMap.put(RandomType.RANDOM, templateFailedPercentage);

        templateResult = nonOverlappingTemplateTest(extractedSessionIdArray, TEMPLATE_TEST_BLOCK_SIZE, MINIMUM_P_VALUE);
        if (templateResult.get(RngConstants.TEMPLATE_CONSTANTS.TEST_RESULT) == 0) {
            LOGGER.debug("TEMPLATE_TEST SessionID : FAILED");
            nonOverlappingTemplateList.add(RandomType.SESSION_ID);
        } else {
            LOGGER.debug("TEMPLATE_TEST SessionID : PASSED");
        }
        templateFailedPercentage = templateResult.get(RngConstants.TEMPLATE_CONSTANTS.PERCENTAGE);
        LOGGER.debug("TEMPLATE_TEST SessionID Failed Test Percentage : " + (templateFailedPercentage * 100));
        nonOverlappingTemplatePercentagesMap.put(RandomType.SESSION_ID, templateFailedPercentage);

        templateResult = nonOverlappingTemplateTest(extractedIvArray, TEMPLATE_TEST_BLOCK_SIZE, MINIMUM_P_VALUE);
        if (templateResult.get(RngConstants.TEMPLATE_CONSTANTS.TEST_RESULT) == 0) {
            LOGGER.debug("TEMPLATE_TEST IV : FAILED");
            nonOverlappingTemplateList.add(RandomType.IV);
        } else {
            LOGGER.debug("TEMPLATE_TEST IV : PASSED");
        }
        templateFailedPercentage = templateResult.get(RngConstants.TEMPLATE_CONSTANTS.PERCENTAGE);
        LOGGER.debug("TEMPLATE_TEST IV Failed Test Percentage : " + (templateFailedPercentage * 100));
        nonOverlappingTemplatePercentagesMap.put(RandomType.IV, templateFailedPercentage);

        templateResult = nonOverlappingTemplateTest(testSequence, TEMPLATE_TEST_BLOCK_SIZE, MINIMUM_P_VALUE);
        if (templateResult.get(RngConstants.TEMPLATE_CONSTANTS.TEST_RESULT) == 0) {
            LOGGER.debug("TEMPLATE_TEST FullSequence : FAILED");
            nonOverlappingTemplateList.add(RandomType.COMPLETE_SEQUENCE);
        } else {
            LOGGER.debug("TEMPLATE_TEST FullSequence : PASSED");
        }
        templateFailedPercentage = templateResult.get(RngConstants.TEMPLATE_CONSTANTS.PERCENTAGE);
        LOGGER.debug("TEMPLATE_TEST FullSequence Failed Test Percentage : " + (templateFailedPercentage * 100));
        nonOverlappingTemplatePercentagesMap.put(RandomType.COMPLETE_SEQUENCE, templateFailedPercentage);

        // /////////////////////////////////////////////////
        report.putTemplatePercentageMap(nonOverlappingTemplatePercentagesMap);
        report.putTemplateResult(nonOverlappingTemplateList);
        // ////////////////////////////////////////////////
        LOGGER.debug("============================================================================================");

        // serialTest(testSequence, 16));
        LOGGER.debug("Serial Test currently deactivated.");
        LOGGER.debug("============================================================================================");

        // ////////////////////////////////////////////////
        if (approximateEntropyTest(extractedRandomArray, ENTROPY_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("ENTROPY_TEST ServerHelloRandom : FAILED");
            entropyList.add(RandomType.RANDOM);
        } else {
            LOGGER.debug("ENTROPY_TEST ServerHelloRandom : PASSED");
        }
        if (!(extractedSessionIdArray.length == 0)
            && approximateEntropyTest(extractedSessionIdArray, ENTROPY_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("ENTROPY_TEST SessionID : FAILED");
            entropyList.add(RandomType.SESSION_ID);
        } else {
            LOGGER.debug("ENTROPY_TEST SessionID : PASSED");
        }
        if (!(extractedIvArray.length == 0)
            && approximateEntropyTest(extractedIvArray, ENTROPY_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("ENTROPY_TEST IV : FAILED");
            entropyList.add(RandomType.IV);
        } else {
            LOGGER.debug("ENTROPY_TEST IV : PASSED");
        }
        if (approximateEntropyTest(testSequence, ENTROPY_TEST_BLOCK_SIZE) <= MINIMUM_P_VALUE) {
            LOGGER.debug("ENTROPY_TEST FullSequence : FAILED");
            entropyList.add(RandomType.COMPLETE_SEQUENCE);
        } else {
            LOGGER.debug("ENTROPY_TEST FullSequence : PASSED");
        }
        // /////////////////////////////////////////////////
        report.putEntropyResult(entropyList);
        // ////////////////////////////////////////////////
        LOGGER.debug("============================================================================================");

        // cusumTest(testSequence, true)); // Forward
        // cusumTest(testSequence, false)); // Reverse
        LOGGER.debug("Cusum Test currently deactivated.");
        LOGGER.debug("============================================================================================");

        // ////////////////////////////////////////////////
    }

    /**
     * Simple Test creating a hash-set of random-values and checks for every random if it is already inserted. If no
     * collision was found then no duplicates are present.
     * 
     * @param  byteSequence
     *                      Array of random byte sequences
     * @return              TRUE if duplicates were found
     */
    private boolean testForDuplicates(ComparableByteArray[] byteSequence) {
        Set<ComparableByteArray> entryList = new HashSet<ComparableByteArray>();
        for (ComparableByteArray byteArray : byteSequence) {
            if (entryList.contains(byteArray)) {
                return true;
            }
            entryList.add(byteArray);
        }
        return false;
    }

}
