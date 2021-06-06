/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsscanner.serverscanner.guideline.ConditionalGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class AnalyzedPropertyGuidelineCheck extends ConditionalGuidelineCheck {

    private AnalyzedProperty property;
    private TestResult result;

    @Override
    public GuidelineCheckStatus evaluateStatus(SiteReport report) {
        TestResult reportResult = report.getResult(this.property);
        if (reportResult == null) {
            return GuidelineCheckStatus.UNCERTAIN;
        }
        switch (reportResult) {
            case UNCERTAIN:
            case COULD_NOT_TEST:
            case CANNOT_BE_TESTED:
            case ERROR_DURING_TEST:
            case NOT_TESTED_YET:
            case TIMEOUT:
                return GuidelineCheckStatus.UNCERTAIN;
        }
        return reportResult.equals(this.result) ? GuidelineCheckStatus.PASSED : GuidelineCheckStatus.FAILED;
    }

    public AnalyzedProperty getProperty() {
        return property;
    }

    public void setProperty(AnalyzedProperty property) {
        this.property = property;
    }

    public TestResult getResult() {
        return result;
    }

    public void setResult(TestResult result) {
        this.result = result;
    }
}
