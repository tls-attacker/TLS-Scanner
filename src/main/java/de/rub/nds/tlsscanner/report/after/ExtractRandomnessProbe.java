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
import de.rub.nds.tlsscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.statistics.RandomEvaluationResult;

import java.util.*;
import java.io.PrintStream;

import org.apache.commons.math3.distribution.NormalDistribution;
import org.jtransforms.fft.DoubleFFT_1D;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.math3.special.Gamma;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.Math.*;
import static org.apache.commons.math3.special.Erf.erfc;

public class ExtractRandomnessProbe extends AfterProbe {

    private static final Logger LOGGER = LogManager.getLogger();

    private final static byte[] HELLO_RETRY_REQUEST_CONST = ArrayConverter
            .hexStringToByteArray("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    // See NIST SP 800-22 2.4.4 (3)
    private final static int[][] LONGEST_RUN_VALUES = { { 8, 3, 16 }, { 128, 5, 49 }, { 10000, 6, 75 } };
    private final static int[][] LONGEST_RUN_EXPECTATION = { { 1, 2, 3, 4 }, { 4, 5, 6, 7, 8, 9 },
            { 10, 11, 12, 13, 14, 15, 16 } };
    private final static double[][] LONGEST_RUN_PROBABILITIES = { { 0.2148, 0.3672, 0.2305, 0.1875 },
            { 0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124 },
            { 0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727 } };
    private final static String[][] TEMPLATE_NINE = { { "000000001" }, { "000000011" }, { "000000101" },
            { "000000111" }, { "000001001" }, { "000001011" }, { "000001101" }, { "000001111" }, { "000010001" },
            { "000010011" }, { "000010101" }, { "000010111" }, { "000011001" }, { "000011011" }, { "000011101" },
            { "000011111" }, { "000100011" }, { "000100101" }, { "000100111" }, { "000101001" }, { "000101011" },
            { "000101101" }, { "000101111" }, { "000110011" }, { "000110101" }, { "000110111" }, { "000111001" },
            { "000111011" }, { "000111101" }, { "000111111" }, { "001000011" }, { "001000101" }, { "001000111" },
            { "001001011" }, { "001001101" }, { "001001111" }, { "001010011" }, { "001010101" }, { "001010111" },
            { "001011011" }, { "001011101" }, { "001011111" }, { "001100101" }, { "001100111" }, { "001101011" },
            { "001101101" }, { "001101111" }, { "001110101" }, { "001110111" }, { "001111011" }, { "001111101" },
            { "001111111" }, { "010000011" }, { "010000111" }, { "010001011" }, { "010001111" }, { "010010011" },
            { "010010111" }, { "010011011" }, { "010011111" }, { "010100011" }, { "010100111" }, { "010101011" },
            { "010101111" }, { "010110011" }, { "010110111" }, { "010111011" }, { "010111111" }, { "011000111" },
            { "011001111" }, { "011010111" }, { "011011111" }, { "011101111" }, { "011111111" }, { "100000000" },
            { "100010000" }, { "100100000" }, { "100101000" }, { "100110000" }, { "100111000" }, { "101000000" },
            { "101000100" }, { "101001000" }, { "101001100" }, { "101010000" }, { "101010100" }, { "101011000" },
            { "101011100" }, { "101100000" }, { "101100100" }, { "101101000" }, { "101101100" }, { "101110000" },
            { "101110100" }, { "101111000" }, { "101111100" }, { "110000000" }, { "110000010" }, { "110000100" },
            { "110001000" }, { "110001010" }, { "110010000" }, { "110010010" }, { "110010100" }, { "110011000" },
            { "110011010" }, { "110100000" }, { "110100010" }, { "110100100" }, { "110101000" }, { "110101010" },
            { "110101100" }, { "110110000" }, { "110110010" }, { "110110100" }, { "110111000" }, { "110111010" },
            { "110111100" }, { "111000000" }, { "111000010" }, { "111000100" }, { "111000110" }, { "111001000" },
            { "111001010" }, { "111001100" }, { "111010000" }, { "111010010" }, { "111010100" }, { "111010110" },
            { "111011000" }, { "111011010" }, { "111011100" }, { "111100000" }, { "111100010" }, { "111100100" },
            { "111100110" }, { "111101000" }, { "111101010" }, { "111101100" }, { "111101110" }, { "111110000" },
            { "111110010" }, { "111110100" }, { "111110110" }, { "111111000" }, { "111111010" }, { "111111100" },
            { "111111110" } };

    @Override
    public void analyze(SiteReport report) {

        if (report.getExtractedValueContainerMap().isEmpty()) {
            report.setRandomEvaluationResult(RandomEvaluationResult.NO_DUPLICATES);
            return;
        }

        ExtractedValueContainer container = report.getExtractedValueContainerMap().get(TrackableValueType.RANDOM);
        ExtractedValueContainer tempContainter = new ExtractedValueContainer(TrackableValueType.RANDOM);
        for (Object o : container.getExtractedValueList()) {
            ComparableByteArray random = (ComparableByteArray) o;
            if (!Arrays.equals(HELLO_RETRY_REQUEST_CONST, random.getArray())) {
                tempContainter.put(o);
            }
        }

        container = report.getExtractedValueContainerMap().get(TrackableValueType.SESSION_ID);
        ExtractedValueContainer tempContainter2 = new ExtractedValueContainer(TrackableValueType.SESSION_ID);
        for (Object o : container.getExtractedValueList()) {
            tempContainter2.put(o);
        }

        container = report.getExtractedValueContainerMap().get(TrackableValueType.PUBKEY);
        ExtractedValueContainer tempContainer3 = new ExtractedValueContainer(TrackableValueType.PUBKEY);
        if (!container.getExtractedValueList().isEmpty()) {
            for (Object o : container.getExtractedValueList()) {
                tempContainer3.put(o);
            }
        }

        container = report.getExtractedValueContainerMap().get(TrackableValueType.IV);
        ExtractedValueContainer tempContainer4 = new ExtractedValueContainer(TrackableValueType.IV);
        if (!container.getExtractedValueList().isEmpty()) {
            for (Object o : container.getExtractedValueList()) {
                tempContainer4.put(o);
            }
        }

        String host_name_full = report.getHost();
        String rng_file = host_name_full.substring(0, host_name_full.length() - 4);
        List<ComparableByteArray> full_byte_sequences = new ArrayList<ComparableByteArray>();

        try {
            PrintStream random_file = new PrintStream(rng_file);

            // Extract Server Hello Random Bytes
            random_file.println("SERVER RANDOM");
            for (Object o : tempContainter.getExtractedValueList()) {
                ComparableByteArray byteArrayRNG = (ComparableByteArray) o;
                full_byte_sequences.add(byteArrayRNG);
                String random_bytes = "";

                for (byte b : byteArrayRNG.getArray()) {
                    random_bytes = random_bytes + String.format("%02X", b);
                }

                random_file.println(random_bytes);
            }

            // Extract Server Hello Session ID
            random_file.println("SESSION ID");
            for (Object o : tempContainter2.getExtractedValueList()) {
                ComparableByteArray byteArrayRNG = (ComparableByteArray) o;
                full_byte_sequences.add(byteArrayRNG);
                String random_bytes = "";

                for (byte b : byteArrayRNG.getArray()) {
                    random_bytes = random_bytes + String.format("%02X", b);
                }

                random_file.println(random_bytes);
            }

            // Extract Server EC Public Key
            random_file.println("EC PUBLIC KEY");
            for (Object o : tempContainer3.getExtractedValueList()) {
                ComparableByteArray byteArrayRNG = (ComparableByteArray) o;
                full_byte_sequences.add(byteArrayRNG);
                String random_bytes = "";

                for (byte b : byteArrayRNG.getArray()) {
                    random_bytes = random_bytes + String.format("%02X", b);
                }

                random_file.println(random_bytes);
            }

            // Extract Application IV
            random_file.println("IV");
            for (Object o : tempContainer4.getExtractedValueList()) {
                ComparableByteArray byteArrayRNG = (ComparableByteArray) o;
                full_byte_sequences.add(byteArrayRNG);
                String random_bytes = "";

                for (byte b : byteArrayRNG.getArray()) {
                    random_bytes = random_bytes + String.format("%02X", b);
                }

                random_file.println(random_bytes);
            }

            random_file.close();

        } catch (IOException e) {
            LOGGER.warn("IOEXCEPTION!");
            LOGGER.warn(e.toString());
        }

        // String test =
        // "1100100100001111110110101010001000100001011010001100001000110100110001001100011001100010100010111000";
        // byte[] test1 = new BigInteger(test, 2).toByteArray();
        // ComparableByteArray test2 = new ComparableByteArray(test1);
        // ComparableByteArray[] test3 = new ComparableByteArray[] { test2 };
        // LOGGER.warn(frequencyTest(test3, 10));

        ComparableByteArray[] test = new ComparableByteArray[full_byte_sequences.size()];
        ComparableByteArray[] test2 = full_byte_sequences.toArray(test);
        LOGGER.warn("============================================================================================");
        LOGGER.warn("P-Value of Monobit : " + frequencyTest(test2, 1));
        LOGGER.warn("============================================================================================");
        LOGGER.warn("P-Value of Frequency-Test with Block size 10 : " + frequencyTest(test2, 128));
        LOGGER.warn("============================================================================================");
        LOGGER.warn("P-Value of RunsTest : " + runsTest(test2));
        LOGGER.warn("============================================================================================");
        LOGGER.warn("P-Value of longestRunWithinABlock : " + longestRunWithinBlock(test2, 8));
        LOGGER.warn("============================================================================================");
        LOGGER.warn("P-Value of Discrete Fourier Test : " + discreteFourierTest(test2));
        LOGGER.warn("============================================================================================");
        LOGGER.warn("Failed Tests-ratio of NonOverlappingTemplate Test : " + nonOverlappingTemplateTest(test2, 9));
        LOGGER.warn("Its hard to say what number of nonOverlappingTemplate Tests are concerning.");
        LOGGER.warn("============================================================================================");
        LOGGER.warn("Average P-Value returned by Serial Test : " + serialTest(test2, 16));
        LOGGER.warn("============================================================================================");
        LOGGER.warn("P-Value of Approximate Entropy Test : " + approximateEntropyTest(test2, 10));
        LOGGER.warn("============================================================================================");
        LOGGER.warn("P-Value of Cumulative Sums Test : " + cusumTest(test2, true));
        LOGGER.warn("P-Value of Cumulative Sums (REVERSE) Test :" + cusumTest(test, false));
        LOGGER.warn("============================================================================================");
    }

    /**
     * TODO: REWORK THIS! Compare not the objects, but the individual entries of
     * the byteArrays
     * 
     * @param byteSequence
     * @return
     */
    private boolean testForDuplicates(ComparableByteArray[] byteSequence) {
        Set<Integer> entryList = new HashSet<Integer>();
        for (ComparableByteArray i : byteSequence) {
            if (entryList.contains(i.hashCode())) {
                return true;
            }
            entryList.add(i.hashCode());
        }
        return false;
    }

    private Double cusumTest(ComparableByteArray[] byteSequence, boolean forwardMode) {
        double pValue = 0.0;
        String fullSequence = "";

        for (ComparableByteArray randomString : byteSequence) {
            fullSequence = fullSequence + byteArrayToBitString(randomString);
        }

        int[] convertedSequence = new int[fullSequence.length()];

        // Convert 0 to -1 and 1 to +1
        for (int i = 0; i < fullSequence.length(); i++) {
            convertedSequence[i] = 2 * Character.getNumericValue(fullSequence.charAt(i)) - 1;
        }

        if (!forwardMode) {
            ArrayUtils.reverse(convertedSequence);
        }

        int cuSums[] = new int[fullSequence.length()];

        for (int i = 0; i < fullSequence.length(); i++) {
            for (int j = 0; j < i + 1; j++) {
                cuSums[i] = cuSums[i] + convertedSequence[j];
            }
        }

        IntSummaryStatistics stat = Arrays.stream(cuSums).summaryStatistics();
        int min = stat.getMin();
        int max = stat.getMax();

        int z;

        if (abs(min) > max) {
            z = abs(min);
        } else {
            z = max;
        }

        NormalDistribution dst = new NormalDistribution();

        double probSum1 = 0.0;
        double probSum2 = 0.0;

        int sumStart = ((-fullSequence.length() / z) + 1) / 4;
        int sumEnd = ((fullSequence.length() / z) - 1) / 4;

        for (int i = sumStart; i < sumEnd + 1; i++) {
            probSum1 = probSum1 + dst.cumulativeProbability(((4 * i + 1) * z) / sqrt(fullSequence.length()));
            probSum1 = probSum1 - dst.cumulativeProbability(((4 * i - 1) * z) / sqrt(fullSequence.length()));
        }

        sumStart = ((-fullSequence.length() / z) - 3) / 4;
        sumEnd = ((fullSequence.length() / z) - 1) / 4;

        for (int i = sumStart; i < sumEnd + 1; i++) {
            probSum2 = probSum2 + dst.cumulativeProbability(((4 * i + 3) * z) / sqrt(fullSequence.length()));
            probSum2 = probSum2 - dst.cumulativeProbability(((4 * i + 1) * z) / sqrt(fullSequence.length()));
        }

        pValue = 1 - probSum1 + probSum2;

        return pValue;
    }

    /***
     *
     * @param byteSequence
     * @param blockLength
     * @return
     */
    private Double approximateEntropyTest(ComparableByteArray[] byteSequence, int blockLength) {
        // TODO: Select m and n such that m < log_2)(n) - 5
        // TODO: ie. for 1096 recommend is blockLength of 5
        double pValue = 0.0;
        String fullSequence = "";

        for (ComparableByteArray randomString : byteSequence) {
            fullSequence = fullSequence + byteArrayToBitString(randomString);
        }

        String extendedSequence = fullSequence + fullSequence.substring(0, blockLength - 1);
        String extendedSecondSequence = fullSequence + fullSequence.substring(0, blockLength);

        // Round 1
        String[] mBitSequence = generateAllBitStrings(blockLength);
        int[] mBitSequenceCount = new int[mBitSequence.length];
        double phi = 0.0;

        for (int i = 0; i < fullSequence.length(); i++) {
            int index = ArrayUtils.indexOf(mBitSequence, extendedSequence.substring(i, i + blockLength));
            mBitSequenceCount[index]++;
        }

        for (int i = 0; i < mBitSequence.length; i++) {
            if (mBitSequenceCount[i] > 0) {
                double proportion = (double) mBitSequenceCount[i] / fullSequence.length();
                phi = phi + (proportion) * log(proportion);
            }
        }

        // Round 2
        String[] mPlusOneBitSequence = generateAllBitStrings(blockLength + 1);
        int[] mPlusOneBitCount = new int[mPlusOneBitSequence.length];
        double phiTwo = 0.0;

        for (int i = 0; i < fullSequence.length(); i++) {
            int index = ArrayUtils.indexOf(mPlusOneBitSequence,
                    extendedSecondSequence.substring(i, i + blockLength + 1));
            mPlusOneBitCount[index]++;
        }

        for (int i = 0; i < mPlusOneBitSequence.length; i++) {
            if (mPlusOneBitCount[i] > 0) {
                double proportion = (double) mPlusOneBitCount[i] / fullSequence.length();
                phiTwo = phiTwo + (proportion) * log(proportion);
            }
        }

        double chiSquare = 2.0 * fullSequence.length() * (log(2) - (phi - phiTwo));
        pValue = Gamma.regularizedGammaQ(pow(2, blockLength - 1), chiSquare / 2.0);

        return pValue;
    }

    /***
     *
     * @param byteSequence
     * @param blockLength
     * @return
     */
    private Double serialTest(ComparableByteArray[] byteSequence, int blockLength) {
        double pValue = 0.0;
        String fullSequence = "";

        for (ComparableByteArray randomString : byteSequence) {
            fullSequence = fullSequence + byteArrayToBitString(randomString);
        }

        // Extend the input sequence by appending beginning bits to the end of
        // the full sequence
        String extendedFullSequence = fullSequence + fullSequence.substring(0, blockLength - 1);
        String extendedFullSequenceMinusOne = fullSequence + fullSequence.substring(0, blockLength - 2);
        String extendedFullSequenceMinusTwo = fullSequence + fullSequence.substring(0, blockLength - 3);

        // Determine frequency of all possible overlapping blockLength bit
        // blocks, all possible blockLength-1 bit blocks
        // all possible overlapping blockLength-2 bit blocks.
        String[] blockLengthBlocks = generateAllBitStrings(blockLength);
        int[] blockOccurrence = new int[blockLengthBlocks.length];
        // TODO: IMPLEMENT CHECK FOR BLOCKLENGTH-1 <= 0 !
        String[] blockLengthMinusOneBlocks = generateAllBitStrings(blockLength - 1);
        int[] blockOccurrenceMinusOne = new int[blockLengthMinusOneBlocks.length];
        String[] blockLengthMinusTwoBlocks = generateAllBitStrings(blockLength - 2);
        int[] blockOccurrenceMinusTwo = new int[blockLengthMinusTwoBlocks.length];

        // one for loop through the full sequence
        for (int currentIndex = 0; currentIndex < fullSequence.length(); currentIndex++) {
            // Find sequence in array and add to count of that particular bit
            // string
            // through blockLengthBlocks?
            String compareString = extendedFullSequence.substring(currentIndex, blockLength + currentIndex);
            for (int i = 0; i < blockLengthBlocks.length; i++) {
                if (compareString.equals(blockLengthBlocks[i])) {
                    blockOccurrence[i]++;
                    break;
                }
            }
            // int index = ArrayUtils.indexOf(blockLengthBlocks,
            // extendedFullSequence.substring(currentIndex, blockLength +
            // currentIndex));
            // blockOccurrence[index]++;

            compareString = extendedFullSequenceMinusOne.substring(currentIndex, blockLength + currentIndex - 1);
            for (int i = 0; i < blockLengthMinusOneBlocks.length; i++) {
                if (compareString.equals(blockLengthMinusOneBlocks[i])) {
                    blockOccurrenceMinusOne[i]++;
                    break;
                }
            }
            // index = ArrayUtils.indexOf(blockLengthMinusOneBlocks,
            // extendedFullSequenceMinusOne.substring(currentIndex, blockLength
            // + currentIndex - 1));
            // blockOccurrenceMinusOne[index]++;

            compareString = extendedFullSequenceMinusTwo.substring(currentIndex, blockLength + currentIndex - 2);
            for (int i = 0; i < blockLengthMinusTwoBlocks.length; i++) {
                if (compareString.equals(blockLengthMinusTwoBlocks[i])) {
                    blockOccurrenceMinusTwo[i]++;
                    break;
                }
            }
            // index = ArrayUtils.indexOf(blockLengthMinusTwoBlocks,
            // extendedFullSequenceMinusTwo.substring(currentIndex, blockLength
            // + currentIndex - 2));
            // blockOccurrenceMinusTwo[index]++;
        }

        double psi = 0.0;
        double psiMinusOne = 0.0;
        double psiMinusTwo = 0.0;

        for (int i = 0; i < blockLengthBlocks.length; i++) {
            psi = psi + pow(blockOccurrence[i], 2);
        }

        psi = pow(2, blockLength) / ((double) fullSequence.length()) * psi - fullSequence.length();

        for (int i = 0; i < blockLengthMinusOneBlocks.length; i++) {
            psiMinusOne = psiMinusOne + pow(blockOccurrenceMinusOne[i], 2);
        }

        psiMinusOne = pow(2, blockLength - 1) / ((double) fullSequence.length()) * psiMinusOne - fullSequence.length();

        for (int i = 0; i < blockLengthMinusTwoBlocks.length; i++) {
            psiMinusTwo = psiMinusTwo + pow(blockOccurrenceMinusTwo[i], 2);
        }

        psiMinusTwo = pow(2, blockLength - 2) / ((double) fullSequence.length()) * psiMinusTwo - fullSequence.length();

        double delta = psi - psiMinusOne;
        double deltaSquared = psi - 2.0 * psiMinusOne + psiMinusTwo;

        double pValueOne = Gamma.regularizedGammaQ(pow(2, blockLength - 1) / 2.0, delta / 2.0);
        double pValueTwo = Gamma.regularizedGammaQ(pow(2, blockLength - 2) / 2.0, deltaSquared / 2.0);

        LOGGER.warn("SERIAL TEST pValueOne : " + pValueOne);
        LOGGER.warn("SERIAL TEST pValueTwo : " + pValueTwo);

        if (pValueOne >= 0.01 & pValueTwo >= 0.01) {
            LOGGER.warn("SERIAL TEST PASSED!");
        } else {
            LOGGER.warn("SERIAL TEST FAILED!");
        }

        pValue = (pValueOne + pValueTwo) / 2.0;

        return pValue;
    }

    /***
     * Divides the bit sequence into 8 blocks and examines the blocks via a
     * window of templateSize and counts the occurrences of pre-defined
     * templates and compares it to the theoretical mean and variance. This is
     * used to detect non-periodic patterns in the generated sequence. Note,
     * that frequencyTest etc. should be executed before this, as a sequence
     * consisting of only 1's would pass this test with a good p-value.
     * 
     * @param byteSequence
     *            The byte sequence to be examined
     * @param templateSize
     *            The size of the templates which are examined for (NOTE: ONLY
     *            "9" CURRENTLY SUPPORTED)
     * @return The ratio of failed tests to number of tests
     */
    private Double nonOverlappingTemplateTest(ComparableByteArray[] byteSequence, int templateSize) {
        String fullSequence = "";
        int NUMBER_OF_BLOCKS = 8;
        int failedTests = 0;

        if (!(templateSize == 9)) {
            LOGGER.warn("Currently only templateSize of 9 supported!");
            return 0.0;
        }

        for (ComparableByteArray randomString : byteSequence) {
            fullSequence = fullSequence + byteArrayToBitString(randomString);
        }

        // fixed to 8 for this test
        int blockSize = fullSequence.length() / NUMBER_OF_BLOCKS;

        // μ = (M-m+1)/2^m
        double theoMean = (blockSize - templateSize + 1.0) / pow(2, templateSize);
        // σ² = M(1/(2^m) - (2m-1)/(2^(2m)))
        double theoVar = blockSize
                * ((1.0 / pow(2, templateSize)) - (2.0 * templateSize - 1.0) / pow(2, 2.0 * templateSize));

        for (int currentTemplate = 0; currentTemplate < TEMPLATE_NINE.length; currentTemplate++) {
            int[] templateCount = new int[NUMBER_OF_BLOCKS];
            Matcher m = Pattern.compile(".{1," + blockSize + "}").matcher(fullSequence);

            for (int i = 0; i < NUMBER_OF_BLOCKS; i++) {
                String currentBlock = m.find() ? fullSequence.substring(m.start(), m.end()) : "";
                int currentIndex = 0;
                int currentTemplateCount = 0;
                // Check for template until the window reaches the end of the
                // block
                while (currentIndex <= (currentBlock.length() - templateSize)) {
                    String window = currentBlock.substring(currentIndex, currentIndex + templateSize);
                    if (window.equals(TEMPLATE_NINE[currentTemplate][0])) {
                        currentTemplateCount++;
                        currentIndex = currentIndex + templateSize;
                    } else {
                        currentIndex++;
                    }
                }
                templateCount[i] = currentTemplateCount;
            }

            // Calculate P-Values for current Template via theoretical mean and
            // variance.
            // Use templateCount, which has occurrences of template for block i
            // via templateCount[i]
            // Chi-square-fit
            double currentPValue = 0.0;
            double currentChi = 0.0;
            for (int j = 0; j < NUMBER_OF_BLOCKS; j++) {
                currentChi = currentChi + (pow((double) templateCount[j] - theoMean, 2) / theoVar);
            }

            currentPValue = Gamma.regularizedGammaQ(NUMBER_OF_BLOCKS / 2.0, currentChi / 2.0);

            if (!(currentPValue >= 0.01)) {
                // current Template failed the Test
                failedTests++;
            }
        }

        LOGGER.warn("Failed Tests : " + failedTests);

        return (double) failedTests / TEMPLATE_NINE.length;
    }

    /***
     * Test which uses the discrete Fourier Transformation to detect periodic
     * features of the sequence which would indicate a deviation from assumed
     * randomness. Recommended input size is 1000 bits. Shamelessly stolen from
     * https://github.com/stamfest/randomtests/blob/master/src/main/java/net/
     * stamfest/randomtests/nist/DiscreteFourierTransform.java TODO: Even if its
     * "stolen" --> refactor it!!
     * 
     * @param byteSequence
     *            The random byte sequence as a ComparableByteArray array
     * @return p values of the experiment
     */
    private Double discreteFourierTest(ComparableByteArray[] byteSequence) {
        String fullSequence = "";

        for (ComparableByteArray randomString : byteSequence) {
            fullSequence = fullSequence + byteArrayToBitString(randomString);
        }

        int n = fullSequence.length();

        double N_l;
        double N_o;
        double d;

        double upperBound;
        double X[] = new double[n];
        double m[] = new double[n / 2 + 1];

        int i, count;

        for (i = 0; i < n; i++) {
            X[i] = 2 * Character.getNumericValue(fullSequence.charAt(i)) - 1;

        }

        DoubleFFT_1D fft = new DoubleFFT_1D(n);
        fft.realForward(X);

        m[0] = Math.sqrt(X[0] * X[0]);
        /* COMPUTE MAGNITUDE */
        m[n / 2] = Math.sqrt(X[1] * X[1]);

        for (i = 0; i < n / 2 - 1; i++) {
            m[i + 1] = Math.hypot(X[2 * i + 2], X[2 * i + 3]);
        }

        count = 0;
        /* CONFIDENCE INTERVAL */
        upperBound = Math.sqrt(2.995732274 * n);
        for (i = 0; i < n / 2; i++) {
            if (m[i] < upperBound) {
                count++;
            }
        }

        N_l = (double) count;
        /* number of peaks less than h = sqrt(3*n) */
        N_o = (double) 0.95 * n / 2.0;
        d = (N_l - N_o) / Math.sqrt(n / 4.0 * 0.95 * 0.05);
        double p_value = erfc(Math.abs(d) / Math.sqrt(2.0));

        return p_value;
    }

    /***
     * Divides the bit sequence into blocks of size blockLength and counts the
     * longest run of 1's in those blocks. The found number of longest runs are
     * then compared to the expected number of longest runs.
     * 
     * @param byteSequence
     *            The random byte sequence as a ComparableByteArray array
     * @param blockLength
     *            The size of the blocks subdividing the sequence. Allowed
     *            values are 8, 128 and 10^4
     * @return p values of the experiment
     */
    private Double longestRunWithinBlock(ComparableByteArray[] byteSequence, int blockLength) {
        double pValue = 0.0;
        String fullSequence = "";
        short category = -1;
        double chiSquareFit = 0.0;

        for (ComparableByteArray randomString : byteSequence) {
            fullSequence = fullSequence + byteArrayToBitString(randomString);
        }

        if (blockLength == LONGEST_RUN_VALUES[0][0]) {
            category = 0;
            if (fullSequence.length() < 128) {
                LOGGER.warn("Sequence is too short for this block size");
                return pValue;
            }
        }
        if (blockLength == LONGEST_RUN_VALUES[1][0]) {
            category = 1;
            if (fullSequence.length() < 6272) {
                LOGGER.warn("Sequence is too short for this block size");
                return pValue;
            }
        }
        if (blockLength == LONGEST_RUN_VALUES[2][0]) {
            category = 2;
            if (fullSequence.length() < 750000) {
                LOGGER.warn("Sequence is too short for this block size");
                return pValue;
            }
        }

        if (category == -1) {
            LOGGER.warn("longestRunWithinBlock only allows block lengths of 8, 128 and 10^4");
            return pValue;
        }

        if (!(fullSequence == "")) {

            // Discard trailing bits
            Integer numberOfBlocks = (int) floor(fullSequence.length() / blockLength);
            int[] runInBlock = new int[numberOfBlocks];
            List<Integer> distinctLengths = new ArrayList<Integer>();

            // Create Regex-Matcher, which splits the fullSequence into blocks
            // of length numberOfBlocks
            Matcher m = Pattern.compile(".{1," + blockLength + "}").matcher(fullSequence);

            for (int i = 0; i < numberOfBlocks; i++) {
                String currentBlock = m.find() ? fullSequence.substring(m.start(), m.end()) : "";
                int longestRun = 0;
                int runCounter = 0;

                for (int j = 0; j < blockLength; j++) {
                    if (currentBlock.charAt(j) == '1') {
                        runCounter++;
                        longestRun = Math.max(longestRun, runCounter);
                    } else {
                        runCounter = 0;
                    }
                }

                // Take note of distinct longest run lengths
                if (!distinctLengths.contains(longestRun)) {
                    distinctLengths.add(longestRun);
                }
                runInBlock[i] = longestRun;
            }

            // Count how many runs of certain length appear in blocks
            int k = LONGEST_RUN_VALUES[category][1];
            int[][] categoryCount = new int[k + 1][2];
            for (int i = 0; i <= k; i++) {
                categoryCount[i][0] = LONGEST_RUN_EXPECTATION[category][i];
                categoryCount[i][1] = 0;
            }

            for (int length : runInBlock) {
                if (length <= categoryCount[0][0]) {
                    categoryCount[0][1]++;
                    continue;
                }
                if (length >= categoryCount[k][0]) {
                    categoryCount[k][1]++;
                    continue;
                }
                for (int searchIndex = 0; searchIndex < k; searchIndex++) {
                    if (categoryCount[searchIndex][0] == length) {
                        categoryCount[searchIndex][1]++;
                        continue;
                    }
                }
            }

            // Chi-square fitting
            double[] categoryProbabilities = LONGEST_RUN_PROBABILITIES[category];
            int[] categoryExpectation = LONGEST_RUN_EXPECTATION[category];
            double numerator;
            double denominator;
            int currentCountIndex = 0;

            // Exclude first (already processed) and last categoryValue (those
            // are special cases)
            for (int i = 0; i <= k; i++) {
                int occurrences = 0;
                // Start at currentCountIndex, which is the first value greater
                // than categoryExpectation[0]
                for (int j = currentCountIndex; j < categoryCount.length; j++) {
                    if (categoryCount[j][0] == categoryExpectation[i]) {
                        occurrences = categoryCount[j][1];
                        break;
                    }
                }
                numerator = pow((double) occurrences - (double) numberOfBlocks * categoryProbabilities[i], 2);
                denominator = numberOfBlocks * categoryProbabilities[i];
                chiSquareFit = chiSquareFit + (numerator / denominator);

            }

            double a = (double) k / (double) 2;
            double x = chiSquareFit / (double) 2;

            pValue = Gamma.regularizedGammaQ(a, x);
        }

        return pValue;
    }

    /***
     * This Test inspects the total number of runs in a sequence, i.e. the
     * uninterrupted sequences of identical bits. The purpose of this test is to
     * determine whether the number of runs of ones and zeroes are as expected
     * as from random sequences. NOTE: This test requires frequencyTest to be
     * ran beforehand! Recommended Input Size is 100 bits. For cryptographic
     * applications the P-Value should be > 0.01.
     * 
     * @param byteSequence
     *            The sequence of random bytes to be inspected.
     * @return The P-Value resulting from the Test.
     */
    private Double runsTest(ComparableByteArray[] byteSequence) {
        double pValue = 0.0;
        String fullSequence = "";
        int occurences = 0;
        double proportion = 0.0;

        // Run First frequencyTest! If frequencyTest has failed, this Test does
        // not have to be run.

        for (ComparableByteArray randomString : byteSequence) {
            fullSequence = fullSequence + byteArrayToBitString(randomString);
        }

        if (!(fullSequence == "")) {

            occurences = StringUtils.countMatches(fullSequence, "1");
            proportion = (double) occurences / (double) fullSequence.length();

            // Initialize with 1
            int runCounter = 1;
            for (int i = 1; i < fullSequence.length(); i++) {
                // Check if previous Character is identical to current one
                if (!(fullSequence.charAt(i) == fullSequence.charAt(i - 1))) {
                    runCounter++;
                }
            }

            // Chi-square fitting
            double numerator = (double) runCounter - (double) 2 * (double) fullSequence.length() * proportion
                    * ((double) 1 - proportion);
            double denominator = (double) 2 * Math.sqrt(2 * fullSequence.length()) * proportion
                    * ((double) 1 - proportion);

            pValue = erfc(Math.abs(numerator) / denominator);

        }

        return pValue;
    }

    /***
     * Simple Frequency-Test. For truly random sequences, the count of 0 and 1
     * in the bit-sequence should be converging towards 50% in each block. For
     * blockLength 1, the Test is equal to the general Monobit-Test where the
     * number of 0's and 1's are compared on the full Sequence. Recommended
     * minimum-length of bits by NIST: 100. Recommended Block size M : M=>20,
     * M>.01n and N<100, with n = Sequence Length, N = Number of Blocks. For
     * cryptographic Applications the P-Value should be > 0.01
     * 
     * @param byteSequence
     *            A ComparableByteArray-Array of the collected byte sequences in
     *            order
     * @return P-Value of the Test
     */
    private Double frequencyTest(ComparableByteArray[] byteSequence, Integer blockLength) {
        String fullSequence = "";
        double pValue = 0.0;

        for (ComparableByteArray randomString : byteSequence) {
            fullSequence = fullSequence + byteArrayToBitString(randomString);
        }

        if (!(fullSequence == "")) {

            // General Case for frequency Test with blockLength =/= 1
            if (!(blockLength == 1)) {
                // Trailing bits are discarded
                Integer numberOfBlocks = (int) floor(fullSequence.length() / blockLength);
                double[] proportionOfBlocks = new double[numberOfBlocks];

                // Create Regex-Matcher, which splits the fullSequence into
                // blocks
                // of length numberOfBlocks
                Matcher m = Pattern.compile(".{1," + blockLength + "}").matcher(fullSequence);

                for (int i = 0; i < numberOfBlocks; i++) {
                    String currentBlock = m.find() ? fullSequence.substring(m.start(), m.end()) : "";
                    proportionOfBlocks[i] = (double) StringUtils.countMatches(currentBlock, "1") / (double) blockLength;
                }

                // Chi-squared Fitting
                double chiSquareFit = 0.0;
                for (int i = 0; i < numberOfBlocks; i++) {
                    double tmp = proportionOfBlocks[i] - ((double) 1 / (double) 2);
                    chiSquareFit = chiSquareFit + Math.pow(tmp, 2);
                }
                chiSquareFit = (double) 4 * (double) blockLength * chiSquareFit;

                // Incomplete Gamma Function for P-Value computation
                double a = (double) numberOfBlocks / (double) 2;
                double x = chiSquareFit / (double) 2;

                pValue = Gamma.regularizedGammaQ(a, x);

            }
            // Special Case for Block-length == 1
            else {
                Integer zeroMatches = StringUtils.countMatches(fullSequence, "0");
                Integer oneMatches = fullSequence.length() - zeroMatches;
                // Convert 1 to value "1" and 0 "-1"
                Integer bitDifference = oneMatches - zeroMatches;

                double statistics = (double) abs(bitDifference) / sqrt(fullSequence.length());
                // complementary error function
                pValue = erfc(statistics / sqrt(2));
            }

        }
        return pValue;
    }

    /***
     * https://stackoverflow.com/questions/12310017/how-to-convert-a-byte-to-its
     * -binary-string-representation
     * 
     * @param byteArray
     *            A comparableByteArray, which should be returned as a
     *            Bit-String
     * @return a String representing the byte as a sequence of 0's and 1's
     */
    private String byteArrayToBitString(ComparableByteArray byteArray) {
        String bitString = "";
        for (Byte o : byteArray.getArray()) {
            bitString = bitString + Integer.toBinaryString((o & 0xFF) + 0x100).substring(1);
        }
        return bitString;
    }

    /***
     * Small helper method to generate all possible bit strings of certain
     * length
     * 
     * @param blockLength
     * @return
     */
    private String[] generateAllBitStrings(int blockLength) {
        int combinations = (int) pow(2, blockLength);
        String[] bitStrings = new String[combinations];
        for (int i = 0; i < combinations; i++) {
            String representation = Integer.toBinaryString(i);
            bitStrings[i] = String.format("%" + blockLength + "s", representation).replace(' ', '0');
        }
        return bitStrings;
    }

}
