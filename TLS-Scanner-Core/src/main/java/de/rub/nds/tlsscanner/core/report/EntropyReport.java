/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.report;

import de.rub.nds.tlsscanner.core.constants.RandomType;
import java.io.Serializable;

public class EntropyReport implements Serializable {

    private RandomType type;

    private int numberOfValues;

    private int numberOfBytes;

    private boolean duplicates;

    private int numberOfDuplicates;

    private boolean failedFrequencyTest;

    private boolean failedMonoBitTest;

    private boolean failedRunsTest;

    private boolean failedLongestRunTest;

    private boolean failedFourierTest;

    private boolean failedEntropyTest;

    private double failedTemplateTestPercentage;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private EntropyReport() {
        this.type = null;
        this.numberOfValues = 0;
        this.numberOfBytes = 0;
        this.duplicates = false;
        this.numberOfDuplicates = 0;
        this.failedFrequencyTest = false;
        this.failedMonoBitTest = false;
        this.failedRunsTest = false;
        this.failedLongestRunTest = false;
        this.failedFourierTest = false;
        this.failedEntropyTest = false;
        this.failedTemplateTestPercentage = 0.0;
    }

    /**
     * Creates an entropy report with the specified test results.
     *
     * @param type The type of random data analyzed
     * @param numberOfValues The number of values analyzed
     * @param numberOfBytes The number of bytes per value
     * @param duplicates Whether duplicates were found
     * @param numberOfDuplicates The number of duplicate values found
     * @param failedFrequencyTest Whether the frequency test failed
     * @param failedMonoBitTest Whether the mono bit test failed
     * @param failedRunsTest Whether the runs test failed
     * @param failedLongestRunTest Whether the longest run test failed
     * @param failedFourierTest Whether the Fourier test failed
     * @param failedEntropyTest Whether the entropy test failed
     * @param failedTemplateTestPercentage The percentage of failed template tests
     */
    public EntropyReport(
            RandomType type,
            int numberOfValues,
            int numberOfBytes,
            boolean duplicates,
            int numberOfDuplicates,
            boolean failedFrequencyTest,
            boolean failedMonoBitTest,
            boolean failedRunsTest,
            boolean failedLongestRunTest,
            boolean failedFourierTest,
            boolean failedEntropyTest,
            double failedTemplateTestPercentage) {
        this.type = type;
        this.numberOfValues = numberOfValues;
        this.numberOfBytes = numberOfBytes;
        this.duplicates = duplicates;
        this.numberOfDuplicates = numberOfDuplicates;
        this.failedFrequencyTest = failedFrequencyTest;
        this.failedMonoBitTest = failedMonoBitTest;
        this.failedRunsTest = failedRunsTest;
        this.failedLongestRunTest = failedLongestRunTest;
        this.failedFourierTest = failedFourierTest;
        this.failedEntropyTest = failedEntropyTest;
        this.failedTemplateTestPercentage = failedTemplateTestPercentage;
    }

    /**
     * Returns the number of values analyzed.
     *
     * @return The number of values analyzed
     */
    public int getNumberOfValues() {
        return numberOfValues;
    }

    /**
     * Returns the number of bytes per value.
     *
     * @return The number of bytes per value
     */
    public int getNumberOfBytes() {
        return numberOfBytes;
    }

    /**
     * Returns the type of random data analyzed.
     *
     * @return The type of random data
     */
    public RandomType getType() {
        return type;
    }

    /**
     * Returns whether duplicates were found in the analyzed data.
     *
     * @return True if duplicates were found, false otherwise
     */
    public boolean isDuplicates() {
        return duplicates;
    }

    /**
     * Returns the number of duplicate values found.
     *
     * @return The number of duplicate values
     */
    public int getNumberOfDuplicates() {
        return numberOfDuplicates;
    }

    /**
     * Returns whether the frequency test failed.
     *
     * @return True if the frequency test failed, false otherwise
     */
    public boolean isFailedFrequencyTest() {
        return failedFrequencyTest;
    }

    /**
     * Returns whether the mono bit test failed.
     *
     * @return True if the mono bit test failed, false otherwise
     */
    public boolean isFailedMonoBitTest() {
        return failedMonoBitTest;
    }

    /**
     * Returns whether the runs test failed.
     *
     * @return True if the runs test failed, false otherwise
     */
    public boolean isFailedRunsTest() {
        return failedRunsTest;
    }

    /**
     * Returns whether the longest run test failed.
     *
     * @return True if the longest run test failed, false otherwise
     */
    public boolean isFailedLongestRunTest() {
        return failedLongestRunTest;
    }

    /**
     * Returns whether the Fourier test failed.
     *
     * @return True if the Fourier test failed, false otherwise
     */
    public boolean isFailedFourierTest() {
        return failedFourierTest;
    }

    /**
     * Returns whether the entropy test failed.
     *
     * @return True if the entropy test failed, false otherwise
     */
    public boolean isFailedEntropyTest() {
        return failedEntropyTest;
    }

    /**
     * Returns the percentage of failed template tests.
     *
     * @return The percentage of failed template tests
     */
    public double getFailedTemplateTestPercentage() {
        return failedTemplateTestPercentage;
    }
}
