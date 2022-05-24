/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.report.rating;

import de.rub.nds.scanner.core.constants.AnalyzedProperty;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(propOrder = { "result", "influence", "scoreCap", "referencedProperty", "referencedPropertyResult" })
public class PropertyResultRatingInfluencer implements Comparable<PropertyResultRatingInfluencer> {

    @XmlElement(type = TestResults.class, name = "result")
    private TestResult result;

    private Integer influence;

    private Integer scoreCap;

    @XmlAnyElement(lax = true)
    private AnalyzedProperty referencedProperty;

    @XmlElement(type = TestResults.class, name = "referencedPropertyResult")
    private TestResult referencedPropertyResult;

    public PropertyResultRatingInfluencer() {

    }

    public PropertyResultRatingInfluencer(TestResult result, Integer influence) {
        this.result = result;
        this.influence = influence;
    }

    public PropertyResultRatingInfluencer(TestResult result, AnalyzedProperty referencedProperty,
        TestResult referencedPropertyResult) {
        this.result = result;
        this.referencedProperty = referencedProperty;
        this.referencedPropertyResult = referencedPropertyResult;
    }

    public PropertyResultRatingInfluencer(TestResult result, Integer influence, Integer scoreCap) {
        this.result = result;
        this.influence = influence;
        this.scoreCap = scoreCap;
    }

    public TestResult getResult() {
        return result;
    }

    public Integer getInfluence() {
        return influence;
    }

    public Integer getScoreCap() {
        return scoreCap;
    }

    public boolean hasScoreCap() {
        return (scoreCap != null && scoreCap != 0);
    }

    public void setResult(TestResult result) {
        this.result = result;
    }

    public void setInfluence(Integer influence) {
        this.influence = influence;
    }

    public void setScoreCap(Integer scoreCap) {
        this.scoreCap = scoreCap;
    }

    public AnalyzedProperty getReferencedProperty() {
        return referencedProperty;
    }

    public void setReferencedProperty(AnalyzedProperty referencedProperty) {
        this.referencedProperty = referencedProperty;
    }

    public TestResult getReferencedPropertyResult() {
        return referencedPropertyResult;
    }

    public void setReferencedPropertyResult(TestResult referencedPropertyResult) {
        this.referencedPropertyResult = referencedPropertyResult;
    }

    public boolean isBadInfluence() {
        return (influence != null && influence < 0 || scoreCap != null);
    }

    @Override
    public int compareTo(PropertyResultRatingInfluencer t) {
        if (this.getScoreCap() == t.getScoreCap()) {
            return Integer.compare(this.getInfluence(), t.getInfluence());
        }
        if (this.getScoreCap() != null && t.getScoreCap() == null) {
            return -1;
        }
        if (t.getScoreCap() != null && this.getScoreCap() == null) {
            return 1;
        }
        return this.getScoreCap().compareTo(t.getScoreCap());
    }

    @Override
    public String toString() {
        return "PropertyResultRatingInfluencer{" + "result=" + result + ", influence=" + influence + ", scoreCap="
            + scoreCap + ", referencedProperty=" + referencedProperty + ", referencedPropertyResult="
            + referencedPropertyResult + '}';
    }
}
