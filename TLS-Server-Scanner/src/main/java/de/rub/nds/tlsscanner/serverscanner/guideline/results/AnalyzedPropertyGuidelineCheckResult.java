/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;

public class AnalyzedPropertyGuidelineCheckResult extends GuidelineCheckResult {

    private final AnalyzedProperty property;
    private final TestResult expectedResult;
    private final TestResult actualResult;

    public AnalyzedPropertyGuidelineCheckResult(TestResult result, AnalyzedProperty property, TestResult expectedResult,
        TestResult actualResult) {
        super(result);
        this.property = property;
        this.expectedResult = expectedResult;
        this.actualResult = actualResult;
    }

    @Override
    public String display() {
        return property + "=" + actualResult;
    }

    public AnalyzedProperty getProperty() {
        return property;
    }

    public TestResult getExpectedResult() {
        return expectedResult;
    }

    public TestResult getActualResult() {
        return actualResult;
    }
}
