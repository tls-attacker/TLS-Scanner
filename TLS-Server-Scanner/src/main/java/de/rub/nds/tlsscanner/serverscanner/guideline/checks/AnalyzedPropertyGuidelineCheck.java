/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.constants.AnalyzedProperty;
import de.rub.nds.scanner.core.constants.TestResult;
import static de.rub.nds.scanner.core.constants.TestResult.CANNOT_BE_TESTED;
import static de.rub.nds.scanner.core.constants.TestResult.COULD_NOT_TEST;
import static de.rub.nds.scanner.core.constants.TestResult.ERROR_DURING_TEST;
import static de.rub.nds.scanner.core.constants.TestResult.NOT_TESTED_YET;
import static de.rub.nds.scanner.core.constants.TestResult.TIMEOUT;
import static de.rub.nds.scanner.core.constants.TestResult.UNCERTAIN;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.AnalyzedPropertyGuidelineCheckResult;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AnalyzedPropertyGuidelineCheck extends GuidelineCheck {

    private TlsAnalyzedProperty property;

    private TestResult result;

    private AnalyzedPropertyGuidelineCheck() {
        super(null, null);
    }

    public AnalyzedPropertyGuidelineCheck(String name, RequirementLevel requirementLevel, TlsAnalyzedProperty property,
        TestResult result) {
        this(name, requirementLevel, null, property, result);
    }

    public AnalyzedPropertyGuidelineCheck(String name, RequirementLevel requirementLevel,
        GuidelineCheckCondition condition, TlsAnalyzedProperty property, TestResult result) {
        super(name, requirementLevel, condition);
        this.property = property;
        this.result = result;
    }

    @Override
    public GuidelineCheckResult evaluate(ScanReport report) {
        TestResult reportResult = report.getResult(this.property);
        switch (reportResult) {
            case UNCERTAIN:
            case COULD_NOT_TEST:
            case CANNOT_BE_TESTED:
            case ERROR_DURING_TEST:
            case NOT_TESTED_YET:
            case TIMEOUT:
                return new AnalyzedPropertyGuidelineCheckResult(reportResult, property, result, reportResult);
        }
        return new AnalyzedPropertyGuidelineCheckResult(TestResult.of(reportResult.equals(this.result)), property,
            result, reportResult);
    }

    @Override
    public String getId() {
        return "AnalyzedProperty_" + getRequirementLevel() + "_" + property + "_" + result;
    }

    public AnalyzedProperty getProperty() {
        return property;
    }

    public TestResult getResult() {
        return result;
    }

}
