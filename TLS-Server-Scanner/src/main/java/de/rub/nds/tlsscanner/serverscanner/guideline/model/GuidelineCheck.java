/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.model;

import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlType(propOrder = { "condition", "analyzedProperty", "description", "requirementLevel", "result" })
public class GuidelineCheck {

    private GuidelineCheckCondition condition;

    private AnalyzedProperty analyzedProperty;

    private String description;

    private RequirementLevel requirementLevel;

    private TestResult result;

    public GuidelineCheck() {
    }

    public GuidelineCheck(GuidelineCheckCondition condition, AnalyzedProperty analyzedProperty, String description,
        TestResult result) {
        this.condition = condition;
        this.analyzedProperty = analyzedProperty;
        this.description = description;
        this.result = result;
    }

    public GuidelineCheckCondition getCondition() {
        return condition;
    }

    @XmlElement(name = "condition")
    public void setCondition(GuidelineCheckCondition condition) {
        this.condition = condition;
    }

    public AnalyzedProperty getAnalyzedProperty() {
        return analyzedProperty;
    }

    @XmlElement(name = "analyzedProperty")
    public void setAnalyzedProperty(AnalyzedProperty analyzedProperty) {
        this.analyzedProperty = analyzedProperty;
    }

    public String getDescription() {
        return description;
    }

    @XmlElement(name = "description")
    public void setDescription(String description) {
        this.description = description;
    }

    public RequirementLevel getRequirementLevel() {
        return requirementLevel;
    }

    @XmlElement(name = "requirementLevel")
    public void setRequirementLevel(RequirementLevel requirementLevel) {
        this.requirementLevel = requirementLevel;
    }

    public TestResult getResult() {
        return result;
    }

    @XmlElement(name = "result")
    public void setResult(TestResult result) {
        this.result = result;
    }

    @Override
    public String toString() {
        return "GuidelineCheck{" + "condition=" + condition + ", analyzedProperty=" + analyzedProperty
            + ", description='" + description + '\'' + ", requirementLevel=" + requirementLevel + ", result=" + result
            + '}';
    }
}
