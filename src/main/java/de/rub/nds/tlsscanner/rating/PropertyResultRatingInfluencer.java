/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

import javax.xml.bind.annotation.XmlType;

@XmlType(propOrder={"result", "influence", "scoreCap"})
public class PropertyResultRatingInfluencer implements Comparable<PropertyResultRatingInfluencer> {

    private TestResult result;

    private double influence;

    private double scoreCap;

    public PropertyResultRatingInfluencer() {

    }
    
    public PropertyResultRatingInfluencer(TestResult result, double influence) {
        this.result = result;
        this.influence = influence;
    }

    public PropertyResultRatingInfluencer(TestResult result, double influence, double scoreCap) {
        this.result = result;
        this.influence = influence;
        this.scoreCap = scoreCap;
    }

    public TestResult getResult() {
        return result;
    }

    public double getInfluence() {
        return influence;
    }

    public double getScoreCap() {
        return scoreCap;
    }

    public void setResult(TestResult result) {
        this.result = result;
    }

    public void setInfluence(double influence) {
        this.influence = influence;
    }

    public void setScoreCap(double scoreCap) {
        this.scoreCap = scoreCap;
    }
    
    public boolean hasNegativeScore() {
        return (influence < 0 || scoreCap > 0);
    }

    @Override
    public int compareTo(PropertyResultRatingInfluencer t) {
        if(this.getScoreCap() == t.getScoreCap()) {
            return Double.compare(this.getInfluence(), t.getInfluence());
        }
        return Double.compare(this.getScoreCap(), t.getScoreCap());
    }

}
