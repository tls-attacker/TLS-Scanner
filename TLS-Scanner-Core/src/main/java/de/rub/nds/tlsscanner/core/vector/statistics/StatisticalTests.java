/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.statistics;

import static java.lang.Math.*;
import static org.apache.commons.math3.special.Erf.erfc;

import de.rub.nds.tlsscanner.core.constants.RandomnessConstants;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.math3.distribution.NormalDistribution;
import org.apache.commons.math3.special.Gamma;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jtransforms.fft.DoubleFFT_1D;

public class StatisticalTests {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Test checking for increasing cumulative sums when mapping 0 to -1 and 1, comparing the
     * results to the expectation.
     *
     * @param byteSequence Array of random byte sequences
     * @param forwardMode TRUE if forward-mode should be used, FALSE if backwards-mode should be
     *     used
     * @return P-Value of the test
     */
    public static Double cumuluativeSumTest(byte[] byteSequence, boolean forwardMode) {
        String bitString = byteArrayToBitString(byteSequence);
        return cumuluativeSumTest(bitString, forwardMode);
    }

    /**
     * Test checking for increasing cumulative sums when mapping 0 to -1 and 1, comparing the
     * results to the expectation.
     *
     * @param bitString Array of random byte sequences
     * @param forwardMode TRUE if forward-mode should be used, FALSE if backwards-mode should be
     *     used
     * @return P-Value of the test
     */
    public static Double cumuluativeSumTest(String bitString, boolean forwardMode) {
        double pValue;

        if (bitString.length() == 0) {
            return 0.0;
        }

        int[] convertedSequence = new int[bitString.length()];

        // Convert 0 to -1 and 1 to +1
        for (int i = 0; i < bitString.length(); i++) {
            convertedSequence[i] = 2 * Character.getNumericValue(bitString.charAt(i)) - 1;
        }

        if (!forwardMode) {
            ArrayUtils.reverse(convertedSequence);
        }

        int cuSums[] = new int[bitString.length()];

        for (int i = 0; i < bitString.length(); i++) {
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

        int sumStart = ((-bitString.length() / z) + 1) / 4;
        int sumEnd = ((bitString.length() / z) - 1) / 4;

        for (int i = sumStart; i < sumEnd + 1; i++) {
            probSum1 =
                    probSum1
                            + dst.cumulativeProbability(
                                    ((4 * i + 1) * z) / sqrt(bitString.length()));
            probSum1 =
                    probSum1
                            - dst.cumulativeProbability(
                                    ((4 * i - 1) * z) / sqrt(bitString.length()));
        }

        sumStart = ((-bitString.length() / z) - 3) / 4;
        sumEnd = ((bitString.length() / z) - 1) / 4;

        for (int i = sumStart; i < sumEnd + 1; i++) {
            probSum2 =
                    probSum2
                            + dst.cumulativeProbability(
                                    ((4 * i + 3) * z) / sqrt(bitString.length()));
            probSum2 =
                    probSum2
                            - dst.cumulativeProbability(
                                    ((4 * i + 1) * z) / sqrt(bitString.length()));
        }

        pValue = 1 - probSum1 + probSum2;

        return pValue;
    }

    /**
     * * Test to check the frequency of all possible bit-patterns of size blockLength, comparing
     * them to the expectation.
     *
     * @param byteSequence array of random byte values
     * @param blockLength length of bit-patterns to check
     * @return P-Value of the test
     */
    public static Double approximateEntropyTest(byte[] byteSequence, int blockLength) {
        String bitString = byteArrayToBitString(byteSequence);
        return approximateEntropyTest(bitString, blockLength);
    }

    /**
     * * Test to check the frequency of all possible bit-patterns of size blockLength, comparing
     * them to the expectation.
     *
     * @param bitString array of random byte values
     * @param blockLength length of bit-patterns to check
     * @return P-Value of the test
     */
    public static Double approximateEntropyTest(String bitString, int blockLength) {
        // TODO: Select m and n such that m < log_2)(n) - 5
        // TODO: ie. for 1096 recommend is blockLength of 5
        // TODO: currently set to the value best fit for the expected amount of
        // bytes of a scan.
        double pValue;

        if (bitString.length() == 0) {
            return 0.0;
        }

        String extendedSequence = bitString + bitString.substring(0, blockLength - 1);
        String extendedSecondSequence = bitString + bitString.substring(0, blockLength);

        // Round 1
        String[] mBitSequence = generateAllBitStrings(blockLength);
        int[] mBitSequenceCount = new int[mBitSequence.length];
        double phi = 0.0;

        for (int i = 0; i < bitString.length(); i++) {
            int index =
                    ArrayUtils.indexOf(
                            mBitSequence, extendedSequence.substring(i, i + blockLength));
            mBitSequenceCount[index]++;
        }

        for (int i = 0; i < mBitSequence.length; i++) {
            if (mBitSequenceCount[i] > 0) {
                double proportion = (double) mBitSequenceCount[i] / bitString.length();
                phi = phi + (proportion) * log(proportion);
            }
        }

        // Round 2
        String[] mPlusOneBitSequence = generateAllBitStrings(blockLength + 1);
        int[] mPlusOneBitCount = new int[mPlusOneBitSequence.length];
        double phiTwo = 0.0;

        for (int i = 0; i < bitString.length(); i++) {
            int index =
                    ArrayUtils.indexOf(
                            mPlusOneBitSequence,
                            extendedSecondSequence.substring(i, i + blockLength + 1));
            mPlusOneBitCount[index]++;
        }

        for (int i = 0; i < mPlusOneBitSequence.length; i++) {
            if (mPlusOneBitCount[i] > 0) {
                double proportion = (double) mPlusOneBitCount[i] / bitString.length();
                phiTwo = phiTwo + (proportion) * log(proportion);
            }
        }

        double chiSquare = 2.0 * bitString.length() * (log(2) - (phi - phiTwo));
        pValue = Gamma.regularizedGammaQ(pow(2, blockLength - 1), chiSquare / 2.0);

        return pValue;
    }

    /**
     * * Test to check the frequency of all possible overlapping bit patterns of length blockLength,
     * checking it against the expectation.
     *
     * @param byteSequence array of random byte values
     * @param blockLength length of bit-patterns to check
     * @return P-Value of the test
     */
    public static Double serialTest(byte[] byteSequence, int blockLength) {
        String bitString = byteArrayToBitString(byteSequence);
        return serialTest(bitString, blockLength);
    }

    /**
     * * Test to check the frequency of all possible overlapping bit patterns of length blockLength,
     * checking it against the expectation.
     *
     * @param bitString array of random byte values
     * @param blockLength length of bit-patterns to check
     * @return P-Value of the test
     */
    public static Double serialTest(String bitString, int blockLength) {
        double pValue;

        if (bitString.length() == 0) {
            return 0.0;
        }

        // Extend the input sequence by appending beginning bits to the end of
        // the full sequence
        String extendedFullSequence = bitString + bitString.substring(0, blockLength - 1);
        String extendedFullSequenceMinusOne = bitString + bitString.substring(0, blockLength - 2);
        String extendedFullSequenceMinusTwo = bitString + bitString.substring(0, blockLength - 3);

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
        for (int currentIndex = 0; currentIndex < bitString.length(); currentIndex++) {
            // Find sequence in array and add to count of that particular bit
            // string
            // through blockLengthBlocks?
            String compareString =
                    extendedFullSequence.substring(currentIndex, blockLength + currentIndex);
            for (int i = 0; i < blockLengthBlocks.length; i++) {
                if (compareString.equals(blockLengthBlocks[i])) {
                    blockOccurrence[i]++;
                    break;
                }
            }

            compareString =
                    extendedFullSequenceMinusOne.substring(
                            currentIndex, blockLength + currentIndex - 1);
            for (int i = 0; i < blockLengthMinusOneBlocks.length; i++) {
                if (compareString.equals(blockLengthMinusOneBlocks[i])) {
                    blockOccurrenceMinusOne[i]++;
                    break;
                }
            }

            compareString =
                    extendedFullSequenceMinusTwo.substring(
                            currentIndex, blockLength + currentIndex - 2);
            for (int i = 0; i < blockLengthMinusTwoBlocks.length; i++) {
                if (compareString.equals(blockLengthMinusTwoBlocks[i])) {
                    blockOccurrenceMinusTwo[i]++;
                    break;
                }
            }
        }

        double psi = 0.0;
        double psiMinusOne = 0.0;
        double psiMinusTwo = 0.0;

        for (int i = 0; i < blockLengthBlocks.length; i++) {
            psi = psi + pow(blockOccurrence[i], 2);
        }

        psi = pow(2, blockLength) / ((double) bitString.length()) * psi - bitString.length();

        for (int i = 0; i < blockLengthMinusOneBlocks.length; i++) {
            psiMinusOne = psiMinusOne + pow(blockOccurrenceMinusOne[i], 2);
        }

        psiMinusOne =
                pow(2, blockLength - 1) / ((double) bitString.length()) * psiMinusOne
                        - bitString.length();

        for (int i = 0; i < blockLengthMinusTwoBlocks.length; i++) {
            psiMinusTwo = psiMinusTwo + pow(blockOccurrenceMinusTwo[i], 2);
        }

        psiMinusTwo =
                pow(2, blockLength - 2) / ((double) bitString.length()) * psiMinusTwo
                        - bitString.length();

        double delta = psi - psiMinusOne;
        double deltaSquared = psi - 2.0 * psiMinusOne + psiMinusTwo;

        double pValueOne = Gamma.regularizedGammaQ(pow(2, blockLength - 1) / 2.0, delta / 2.0);
        double pValueTwo =
                Gamma.regularizedGammaQ(pow(2, blockLength - 2) / 2.0, deltaSquared / 2.0);

        LOGGER.debug("SERIAL TEST pValueOne : " + pValueOne);
        LOGGER.debug("SERIAL TEST pValueTwo : " + pValueTwo);

        if (pValueOne >= 0.01 & pValueTwo >= 0.01) {
            LOGGER.debug("SERIAL TEST PASSED!");
        } else {
            LOGGER.debug("SERIAL TEST FAILED!");
        }

        pValue = (pValueOne + pValueTwo) / 2.0;

        return pValue;
    }

    /**
     * * Divides the bit sequence into 8 blocks and examines the blocks via a window of templateSize
     * and counts the occurrences of pre-defined templates and compares it to the theoretical mean
     * and variance.This is used to detect non-periodic patterns in the generated sequence. Note,
     * that frequencyTest etc. should be executed before this, as a sequence consisting of only 1's
     * would pass this test with a good p-value.
     *
     * @param byteSequence The byte sequence to be examined
     * @param templateSize The size of the templates which are examined for (NOTE: ONLY "9"
     *     CURRENTLY SUPPORTED)
     * @param minimum_p_value
     * @return The ratio of failed tests to number of tests
     */
    public static Double nonOverlappingTemplateTest(
            byte[] byteSequence, int templateSize, double minimum_p_value) {
        String bitString = byteArrayToBitString(byteSequence);
        return nonOverlappingTemplateTest(bitString, templateSize, minimum_p_value);
    }

    /**
     * * Divides the bit sequence into 8 blocks and examines the blocks via a window of templateSize
     * and counts the occurrences of pre-defined templates and compares it to the theoretical mean
     * and variance.This is used to detect non-periodic patterns in the generated sequence. Note,
     * that frequencyTest etc. should be executed before this, as a sequence consisting of only 1's
     * would pass this test with a good p-value.
     *
     * @param bitString The byte sequence to be examined
     * @param templateSize The size of the templates which are examined for (NOTE: ONLY "9"
     *     CURRENTLY SUPPORTED)
     * @param minimum_p_value
     * @return The ratio of failed tests to number of tests
     */
    public static Double nonOverlappingTemplateTest(
            String bitString, int templateSize, double minimum_p_value) {
        int NUMBER_OF_BLOCKS = 8;
        int failedTests = 0;
        double fisherSum = 0.0;
        double pValue = 0.0;

        if (!(templateSize == 9)) {
            LOGGER.debug("Currently only templateSize of 9 supported!");
            return 0.0;
        }

        if (bitString.length() == 0) {
            return 0.0;
        }

        // fixed to 8 for this test
        int blockSize = bitString.length() / NUMBER_OF_BLOCKS;

        // μ = (M-m+1)/2^m
        double theoMean = (blockSize - templateSize + 1.0) / pow(2, templateSize);
        // σ² = M(1/(2^m) - (2m-1)/(2^(2m)))
        double theoVar =
                blockSize
                        * ((1.0 / pow(2, templateSize))
                                - (2.0 * templateSize - 1.0) / pow(2, 2.0 * templateSize));

        for (int currentTemplate = 0;
                currentTemplate < RandomnessConstants.TEMPLATE_NINE.length;
                currentTemplate++) {
            int[] templateCount = new int[NUMBER_OF_BLOCKS];
            Matcher m = Pattern.compile(".{1," + blockSize + "}").matcher(bitString);

            for (int i = 0; i < NUMBER_OF_BLOCKS; i++) {
                String currentBlock = m.find() ? bitString.substring(m.start(), m.end()) : "";
                int currentIndex = 0;
                int currentTemplateCount = 0;
                // Check for template until the window reaches the end of the
                // block
                while (currentIndex <= (currentBlock.length() - templateSize)) {
                    String window =
                            currentBlock.substring(currentIndex, currentIndex + templateSize);
                    if (window.equals(RandomnessConstants.TEMPLATE_NINE[currentTemplate][0])) {
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

            fisherSum = fisherSum + Math.log(currentPValue);
        }

        // Use Fisher's Method to combine the p-values to one p-value
        double fisherResult = (-2) * fisherSum;
        if (Double.isInfinite(fisherResult)) {
            LOGGER.debug("P Value is " + 0);
        } else {
            // Using Fishers Method we get Chi Square Distribution with
            // TEMPLATE_NINE.length * 2 degrees of Freedom.
            pValue =
                    Gamma.regularizedGammaQ(
                            RandomnessConstants.TEMPLATE_NINE.length, fisherResult / 2.0);
            LOGGER.debug("P Value is : " + pValue);
        }
        LOGGER.debug("Failed Tests : " + failedTests);

        double failurePercent = (double) failedTests / RandomnessConstants.TEMPLATE_NINE.length;
        return failurePercent;
    }

    /**
     * * Test which uses the discrete Fourier Transformation to detect periodic features of the
     * sequence which would indicate a deviation from assumed randomness. Recommended input size is
     * 1000 bits.
     *
     * <p>Shamelessly stolen from
     * https://github.com/stamfest/randomtests/blob/master/src/main/java/net/
     * stamfest/randomtests/nist/DiscreteFourierTransform.java
     *
     * @param byteSequence The random byte sequence as a ComparableByteArray array
     * @return p values of the experiment
     */
    public static Double discreteFourierTest(byte[] byteSequence) {
        String bitString = byteArrayToBitString(byteSequence);
        return discreteFourierTest(bitString);
    }

    /**
     * * Test which uses the discrete Fourier Transformation to detect periodic features of the
     * sequence which would indicate a deviation from assumed randomness. Recommended input size is
     * 1000 bits.
     *
     * <p>Shamelessly stolen from
     * https://github.com/stamfest/randomtests/blob/master/src/main/java/net/
     * stamfest/randomtests/nist/DiscreteFourierTransform.java
     *
     * @param bitString The random byte sequence as a ComparableByteArray array
     * @return p values of the experiment
     */
    public static Double discreteFourierTest(String bitString) {
        int n = bitString.length();

        if (n == 0) {
            LOGGER.debug("Only Sequences longer than 0 are allowed.");
            return 0.0;
        }

        double N_l;
        double N_o;
        double d;

        double upperBound;
        double X[] = new double[n];
        double m[] = new double[n / 2 + 1];

        int i, count;

        for (i = 0; i < n; i++) {
            X[i] = 2 * Character.getNumericValue(bitString.charAt(i)) - 1;
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

    /**
     * * Divides the bit sequence into blocks of size blockLength and counts the longest run of 1's
     * in those blocks. The found number of longest runs are then compared to the expected number of
     * longest runs.
     *
     * @param byteSequence The random byte sequence as a ComparableByteArray array
     * @param blockLength The size of the blocks subdividing the sequence. Allowed values are 8, 128
     *     and 10^4
     * @return p values of the experiment
     */
    public static Double longestRunWithinBlock(byte[] byteSequence, int blockLength) {
        String bitString = byteArrayToBitString(byteSequence);
        return longestRunWithinBlock(bitString, blockLength);
    }

    /**
     * * Divides the bit sequence into blocks of size blockLength and counts the longest run of 1's
     * in those blocks. The found number of longest runs are then compared to the expected number of
     * longest runs.
     *
     * @param bitString The random byte sequence as a ComparableByteArray array
     * @param blockLength The size of the blocks subdividing the sequence. Allowed values are 8, 128
     *     and 10^4
     * @return p values of the experiment
     */
    public static Double longestRunWithinBlock(String bitString, int blockLength) {
        double pValue = 0.0;
        short category = -1;
        double chiSquareFit = 0.0;

        if (bitString.length() == 0) {
            return 0.0;
        }

        if (blockLength == RandomnessConstants.LONGEST_RUN_VALUES[0][0]) {
            category = 0;
            if (bitString.length() < 128) {
                LOGGER.debug("Sequence is too short for this block size");
                return pValue;
            }
        }
        if (blockLength == RandomnessConstants.LONGEST_RUN_VALUES[1][0]) {
            category = 1;
            if (bitString.length() < 6272) {
                LOGGER.debug("Sequence is too short for this block size");
                return pValue;
            }
        }
        if (blockLength == RandomnessConstants.LONGEST_RUN_VALUES[2][0]) {
            category = 2;
            if (bitString.length() < 750000) {
                LOGGER.debug("Sequence is too short for this block size");
                return pValue;
            }
        }

        if (category == -1) {
            LOGGER.debug("longestRunWithinBlock only allows block lengths of 8, 128 and 10^4");
            return pValue;
        }

        if (!bitString.isEmpty()) {

            // Discard trailing bits
            Integer numberOfBlocks = (int) floor(bitString.length() / blockLength);
            int[] runInBlock = new int[numberOfBlocks];
            List<Integer> distinctLengths = new ArrayList<Integer>();

            // Create Regex-Matcher, which splits the fullSequence into blocks
            // of length numberOfBlocks
            Matcher m = Pattern.compile(".{1," + blockLength + "}").matcher(bitString);

            for (int i = 0; i < numberOfBlocks; i++) {
                String currentBlock = m.find() ? bitString.substring(m.start(), m.end()) : "";
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
            int k = RandomnessConstants.LONGEST_RUN_VALUES[category][1];
            int[][] categoryCount = new int[k + 1][2];
            for (int i = 0; i <= k; i++) {
                categoryCount[i][0] = RandomnessConstants.LONGEST_RUN_EXPECTATION[category][i];
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
            double[] categoryProbabilities =
                    RandomnessConstants.LONGEST_RUN_PROBABILITIES[category];
            int[] categoryExpectation = RandomnessConstants.LONGEST_RUN_EXPECTATION[category];
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
                numerator =
                        pow(
                                (double) occurrences
                                        - (double) numberOfBlocks * categoryProbabilities[i],
                                2);
                denominator = numberOfBlocks * categoryProbabilities[i];
                chiSquareFit = chiSquareFit + (numerator / denominator);
            }

            double a = (double) k / (double) 2;
            double x = chiSquareFit / (double) 2;

            pValue = Gamma.regularizedGammaQ(a, x);
        }

        return pValue;
    }

    /**
     * * This Test inspects the total number of runs in a sequence, i.e. the uninterrupted sequences
     * of identical bits. The purpose of this test is to determine whether the number of runs of
     * ones and zeroes are as expected as from random sequences. NOTE: This test requires
     * frequencyTest to be ran beforehand! Recommended Input Size is 100 bits. For cryptographic
     * applications the P-Value should be &gt; 0.01.
     *
     * @param byteSequence The sequence of random bytes to be inspected.
     * @return The P-Value resulting from the Test.
     */
    public static Double runsTest(byte[] byteSequence) {
        String bitString = byteArrayToBitString(byteSequence);
        return runsTest(bitString);
    }

    /**
     * * This Test inspects the total number of runs in a sequence, i.e. the uninterrupted sequences
     * of identical bits. The purpose of this test is to determine whether the number of runs of
     * ones and zeroes are as expected as from random sequences. NOTE: This test requires
     * frequencyTest to be ran beforehand! Recommended Input Size is 100 bits. For cryptographic
     * applications the P-Value should be &gt; 0.01.
     *
     * @param bitString The sequence of random bytes to be inspected.
     * @return The P-Value resulting from the Test.
     */
    public static Double runsTest(String bitString) {
        double pValue = 0.0;

        int occurences = 0;
        double proportion = 0.0;

        // Run First frequencyTest! If frequencyTest has failed, this Test does
        // not have to be run.
        if (!bitString.isEmpty()) {

            occurences = StringUtils.countMatches(bitString, "1");
            proportion = (double) occurences / (double) bitString.length();

            // Initialize with 1
            int runCounter = 1;
            for (int i = 1; i < bitString.length(); i++) {
                // Check if previous Character is identical to current one
                if (!(bitString.charAt(i) == bitString.charAt(i - 1))) {
                    runCounter++;
                }
            }

            // Chi-square fitting
            double numerator =
                    (double) runCounter
                            - (double) 2
                                    * (double) bitString.length()
                                    * proportion
                                    * ((double) 1 - proportion);
            double denominator =
                    (double) 2
                            * Math.sqrt(2 * bitString.length())
                            * proportion
                            * ((double) 1 - proportion);

            pValue = erfc(Math.abs(numerator) / denominator);
        }

        return pValue;
    }

    /**
     * * Simple Frequency-Test. For truly random sequences, the count of 0 and 1 in the bit-sequence
     * should be converging towards 50% in each block. For blockLength 1, the Test is equal to the
     * general Monobit-Test where the number of 0's and 1's are compared on the full Sequence.
     * Recommended minimum-length of bits by NIST: 100. Recommended Block size M : M=&gt;20,
     * M&gt;.01n and N&lt;100, with n = Sequence Length, N = Number of Blocks. For cryptographic
     * Applications the P-Value should be &gt; 0.01
     *
     * @param byteSequence A ComparableByteArray-Array of the collected byte sequences in order
     * @return P-Value of the Test
     */
    public static Double frequencyTest(byte[] byteSequence, Integer blockLength) {
        String bitString = byteArrayToBitString(byteSequence);
        return frequencyTest(bitString, blockLength);
    }

    /**
     * * Simple Frequency-Test. For truly random sequences, the count of 0 and 1 in the bit-sequence
     * should be converging towards 50% in each block. For blockLength 1, the Test is equal to the
     * general Monobit-Test where the number of 0's and 1's are compared on the full Sequence.
     * Recommended minimum-length of bits by NIST: 100. Recommended Block size M : M=&gt;20,
     * M&gt;.01n and N&lt;100, with n = Sequence Length, N = Number of Blocks. For cryptographic
     * Applications the P-Value should be &gt; 0.01
     *
     * @param bitString A ComparableByteArray-Array of the collected byte sequences in order
     * @return P-Value of the Test
     */
    public static Double frequencyTest(String bitString, Integer blockLength) {
        double pValue = 0.0;
        if (!bitString.isEmpty()) {

            // General Case for frequency Test with blockLength =/= 1
            if (!(blockLength == 1)) {
                // Trailing bits are discarded
                Integer numberOfBlocks = (int) floor(bitString.length() / blockLength);
                double[] proportionOfBlocks = new double[numberOfBlocks];

                // Create Regex-Matcher, which splits the fullSequence into
                // blocks
                // of length numberOfBlocks
                Matcher m = Pattern.compile(".{1," + blockLength + "}").matcher(bitString);

                for (int i = 0; i < numberOfBlocks; i++) {
                    String currentBlock = m.find() ? bitString.substring(m.start(), m.end()) : "";
                    proportionOfBlocks[i] =
                            (double) StringUtils.countMatches(currentBlock, "1")
                                    / (double) blockLength;
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

            } // Special Case for Block-length == 1
            else {
                Integer zeroMatches = StringUtils.countMatches(bitString, "0");
                Integer oneMatches = bitString.length() - zeroMatches;
                // Convert 1 to value "1" and 0 "-1"
                Integer bitDifference = oneMatches - zeroMatches;

                double statistics = (double) abs(bitDifference) / sqrt(bitString.length());
                // complementary error function
                pValue = erfc(statistics / sqrt(2));
            }
        }
        return pValue;
    }

    /**
     * @param byteArray A comparableByteArray, which should be returned as a Bit-String
     * @return a String representing the byte as a sequence of 0's and 1's
     */
    public static String byteArrayToBitString(byte[] byteArray) {
        StringBuilder bitBuilder = new StringBuilder();
        for (Byte o : byteArray) {
            bitBuilder.append(Integer.toBinaryString((o & 0xFF) + 0x100).substring(1));
        }
        return bitBuilder.toString();
    }

    /**
     * * Small helper method to generate all possible bit strings of certain length
     *
     * @param blockLength
     * @return
     */
    private static String[] generateAllBitStrings(int blockLength) {
        int combinations = (int) pow(2, blockLength);
        String[] bitStrings = new String[combinations];
        for (int i = 0; i < combinations; i++) {
            String representation = Integer.toBinaryString(i);
            bitStrings[i] =
                    String.format("%" + blockLength + "s", representation).replace(' ', '0');
        }
        return bitStrings;
    }
}
