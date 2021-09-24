/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.tlsscanner.serverscanner.constants.RandomType;

public class EntropyReport {

    private RandomType type;

    private int numberOfValues;

    private int numberOfBytes;

    private boolean duplicates;

    private boolean failedFrequencyTest;

    private boolean failedMonoBitTest;

    private boolean failedRunsTest;

    private boolean failedLongestRunTest;

    private boolean failedFourierTest;

    private boolean failedEntropyTest;

    private double failedTemplateTestPercentage;

    public EntropyReport(RandomType type, int numberOfValues, int numberOfBytes, boolean duplicates,
        boolean failedFrequencyTest, boolean failedMonoBitTest, boolean failedRunsTest, boolean failedLongestRunTest,
        boolean failedFourierTest, boolean failedEntropyTest, double failedTemplateTestPercentage) {
        this.type = type;
        this.numberOfValues = numberOfValues;
        this.numberOfBytes = numberOfBytes;
        this.duplicates = duplicates;
        this.failedFrequencyTest = failedFrequencyTest;
        this.failedMonoBitTest = failedMonoBitTest;
        this.failedRunsTest = failedRunsTest;
        this.failedLongestRunTest = failedLongestRunTest;
        this.failedFourierTest = failedFourierTest;
        this.failedEntropyTest = failedEntropyTest;
        this.failedTemplateTestPercentage = failedTemplateTestPercentage;
    }

    public int getNumberOfValues() {
        return numberOfValues;
    }

    public int getNumberOfBytes() {
        return numberOfBytes;
    }

    public RandomType getType() {
        return type;
    }

    public boolean isDuplicates() {
        return duplicates;
    }

    public boolean isFailedFrequencyTest() {
        return failedFrequencyTest;
    }

    public boolean isFailedMonoBitTest() {
        return failedMonoBitTest;
    }

    public boolean isFailedRunsTest() {
        return failedRunsTest;
    }

    public boolean isFailedLongestRunTest() {
        return failedLongestRunTest;
    }

    public boolean isFailedFourierTest() {
        return failedFourierTest;
    }

    public boolean isFailedEntropyTest() {
        return failedEntropyTest;
    }

    public double getFailedTemplateTestPercentage() {
        return failedTemplateTestPercentage;
    }

}
