/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.probe.AnalyzedProperty;
import de.rub.nds.scanner.core.probe.result.TestResult;

public class AnalyzedPropertyGuidelineCheckResult extends GuidelineCheckResult {

    private final AnalyzedProperty property;
    private final TestResult expectedResult;
    private final TestResult actualResult;

    public AnalyzedPropertyGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            AnalyzedProperty property,
            TestResult expectedResult,
            TestResult actualResult) {
        super(checkName, adherence);
        this.property = property;
        this.expectedResult = expectedResult;
        this.actualResult = actualResult;
    }

    @Override
    public String toString() {
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
