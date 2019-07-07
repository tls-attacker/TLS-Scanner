/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

public class Influencer implements Comparable<Influencer> {

    private AnalyzedProperty analyzedProperty;
    
    private TestResult result;

    private double influence;

    private Double scoreCap;
    
    public Influencer() {
        
    }

    public Influencer(AnalyzedProperty influencerConstant, TestResult result, double influence, Double scoreCap) {
        this.analyzedProperty = influencerConstant;
        this.result = result;
        this.influence = influence;
        this.scoreCap = scoreCap;
    }

    public AnalyzedProperty getAnalyzedProperty() {
        return analyzedProperty;
    }

    public TestResult getResult() {
        return result;
    }

    public double getInfluence() {
        return influence;
    }

    public Double getScoreCap() {
        return scoreCap;
    }

    public void setAnalyzedProperty(AnalyzedProperty analyzedProperty) {
        this.analyzedProperty = analyzedProperty;
    }

    public void setResult(TestResult result) {
        this.result = result;
    }

    public void setInfluence(double influence) {
        this.influence = influence;
    }

    public void setScoreCap(Double scoreCap) {
        this.scoreCap = scoreCap;
    }

    @Override
    public int compareTo(Influencer t) {
        if (this.getScoreCap() != null && t.getScoreCap() == null) {
            return 1;
        }
        if (this.getScoreCap() == null && t.getScoreCap() != null) {
            return -1;
        }
        if (this.getScoreCap() != null && t.getScoreCap() != null) {
            return Double.compare(this.getScoreCap(), t.getScoreCap());
        }
        return Double.compare(t.getInfluence(), this.getInfluence());
    }

}
