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
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class AnalyzedPropertyGuidelineCheck extends ConditionalGuidelineCheck {

    private AnalyzedProperty property;
    private TestResult result;

    @Override
    public void evaluate(SiteReport report, GuidelineCheckResult result) {
        TestResult reportResult = report.getResult(this.property);
        if (reportResult == null) {
            result.update(GuidelineCheckStatus.UNCERTAIN, "No Test Result available.");
            return;
        }
        switch (reportResult) {
            case UNCERTAIN:
            case COULD_NOT_TEST:
            case CANNOT_BE_TESTED:
            case ERROR_DURING_TEST:
            case NOT_TESTED_YET:
            case TIMEOUT:
                result.update(GuidelineCheckStatus.UNCERTAIN, "Test Result: " + reportResult);
                return;
        }
        if (reportResult.equals(this.result)) {
            result.update(GuidelineCheckStatus.PASSED, this.property + "=" + reportResult);
        } else {
            result.update(GuidelineCheckStatus.FAILED, this.property + "=" + reportResult);
        }
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
