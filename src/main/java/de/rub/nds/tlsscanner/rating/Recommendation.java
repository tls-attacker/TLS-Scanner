/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

public class Recommendation {
    
    private AnalyzedProperty analyzedProperty;
    
    private TestResult result;
    
    private String resultStatus;
    
    private String handlingRecommendation;
    
    public Recommendation() {
        
    }
    
    public Recommendation(AnalyzedProperty analyzedProperty, TestResult result, String resultStatus, String handlingRecommendation) {
        this.analyzedProperty = analyzedProperty;
        this.result = result;
        this.resultStatus = resultStatus;
        this.handlingRecommendation = handlingRecommendation;
    }

    public AnalyzedProperty getAnalyzedProperty() {
        return analyzedProperty;
    }

    public TestResult getResult() {
        return result;
    }
    
    public String getResultStatus() {
        return resultStatus;
    }

    public String getHandlingRecommendation() {
        return handlingRecommendation;
    }

    public void setAnalyzedProperty(AnalyzedProperty analyzedProperty) {
        this.analyzedProperty = analyzedProperty;
    }

    public void setResult(TestResult result) {
        this.result = result;
    }

    public void setResultStatus(String resultStatus) {
        this.resultStatus = resultStatus;
    }

    public void setHandlingRecommendation(String handlingRecommendation) {
        this.handlingRecommendation = handlingRecommendation;
    }
}
