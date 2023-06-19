/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.guideline;

import com.fasterxml.jackson.annotation.JsonInclude;
import de.rub.nds.scanner.core.constants.AnalyzedProperty;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import jakarta.xml.bind.annotation.*;

import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GuidelineCheckCondition {

    @XmlElement(name = "condition")
    @XmlElementWrapper(name = "and")
    private List<GuidelineCheckCondition> and;

    @XmlElement(name = "condition")
    @XmlElementWrapper(name = "or")
    private List<GuidelineCheckCondition> or;

    @XmlAnyElement(lax = true)
    private AnalyzedProperty analyzedProperty;

    @XmlAnyElement(lax = true)
    private TestResult result;

    private GuidelineCheckCondition() {}

    private GuidelineCheckCondition(
            List<GuidelineCheckCondition> and, List<GuidelineCheckCondition> or) {
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

    public void setAnalyzedProperty(AnalyzedProperty analyzedProperty) {
        this.analyzedProperty = analyzedProperty;
    }

    public TestResult getResult() {
        return result;
    }

    public void setResult(TestResult result) {
        this.result = result;
    }

    public List<GuidelineCheckCondition> getAnd() {
        return and;
    }

    public void setAnd(List<GuidelineCheckCondition> and) {
        this.and = and;
    }

    public List<GuidelineCheckCondition> getOr() {
        return or;
    }

    public void setOr(List<GuidelineCheckCondition> or) {
        this.or = or;
    }
}
