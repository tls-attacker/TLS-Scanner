/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import com.fasterxml.jackson.annotation.JsonInclude;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import java.util.List;
import java.util.StringJoiner;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class GuidelineCheckCondition {

    private List<GuidelineCheckCondition> and;
    private List<GuidelineCheckCondition> or;

    private AnalyzedProperty analyzedProperty;
    private TestResult result;

    private GuidelineCheckCondition() {
    }

    private GuidelineCheckCondition(List<GuidelineCheckCondition> and, List<GuidelineCheckCondition> or) {
        this.and = and;
        this.or = or;
    }

    public GuidelineCheckCondition(AnalyzedProperty analyzedProperty, TestResult result) {
        this.analyzedProperty = analyzedProperty;
        this.result = result;
    }

    public static GuidelineCheckCondition and(List<GuidelineCheckCondition> conditions) {
        return new GuidelineCheckCondition(conditions, null);
    }

    public static GuidelineCheckCondition or(List<GuidelineCheckCondition> conditions) {
        return new GuidelineCheckCondition(null, conditions);
    }

    public AnalyzedProperty getAnalyzedProperty() {
        return analyzedProperty;
    }

    @XmlElement(name = "analyzedProperty")
    public void setAnalyzedProperty(AnalyzedProperty analyzedProperty) {
        this.analyzedProperty = analyzedProperty;
    }

    public TestResult getResult() {
        return result;
    }

    @XmlElement(name = "result")
    public void setResult(TestResult result) {
        this.result = result;
    }

    public List<GuidelineCheckCondition> getAnd() {
        return and;
    }

    @XmlElement(name = "condition")
    @XmlElementWrapper(name = "and")
    public void setAnd(List<GuidelineCheckCondition> and) {
        this.and = and;
    }

    public List<GuidelineCheckCondition> getOr() {
        return or;
    }

    @XmlElement(name = "condition")
    @XmlElementWrapper(name = "or")
    public void setOr(List<GuidelineCheckCondition> or) {
        this.or = or;
    }
}
