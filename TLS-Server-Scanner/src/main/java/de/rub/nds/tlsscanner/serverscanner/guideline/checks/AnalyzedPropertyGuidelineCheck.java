/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.AnalyzedPropertyGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAnyElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlSeeAlso;

@XmlRootElement
@XmlSeeAlso({TestResults.class})
@XmlAccessorType(XmlAccessType.FIELD)
public class AnalyzedPropertyGuidelineCheck extends GuidelineCheck<ServerReport> {

    private TlsAnalyzedProperty property;

    @XmlAnyElement(lax = true)
    private TestResult result;

    private AnalyzedPropertyGuidelineCheck() {
        super(null, null);
    }

    public AnalyzedPropertyGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            TlsAnalyzedProperty property,
            TestResult result) {
        this(name, requirementLevel, null, property, result);
    }

    public AnalyzedPropertyGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            TlsAnalyzedProperty property,
            TestResult result) {
        super(name, requirementLevel, condition);
        this.property = property;
        this.result = result;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        TestResult reportResult = report.getResult(this.property);
        switch ((TestResults) reportResult) {
            case UNCERTAIN:
            case COULD_NOT_TEST:
            case CANNOT_BE_TESTED:
            case ERROR_DURING_TEST:
            case NOT_TESTED_YET:
            case TIMEOUT:
                return new AnalyzedPropertyGuidelineCheckResult(
                        getName(), GuidelineAdherence.CHECK_FAILED, property, result, reportResult);
            default:
                break;
        }
        return new AnalyzedPropertyGuidelineCheckResult(
                getName(),
                GuidelineAdherence.of(reportResult.equals(this.result)),
                property,
                result,
                reportResult);
    }

    @Override
    public String toString() {
        return "AnalyzedProperty_" + getRequirementLevel() + "_" + property + "_" + result;
    }

    public TlsAnalyzedProperty getProperty() {
        return property;
    }

    public TestResult getResult() {
        return result;
    }
}
