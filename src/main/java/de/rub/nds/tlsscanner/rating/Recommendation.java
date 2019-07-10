/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;

public class Recommendation {
    
    static final String NO_INFORMATION_FOUND = "No detailed information available";
    
    static final String NO_RECOMMENDATION_FOUND = "No recommendation available";
    
    private AnalyzedProperty analyzedProperty;
    
    private List<PropertyRecommendation> propertyRecommendations;
    
    public Recommendation() {
        propertyRecommendations = new LinkedList<>();
    }
    
    public Recommendation(AnalyzedProperty analyzedProperty, List<PropertyRecommendation> propertyRecommendations) {
        this.analyzedProperty = analyzedProperty;
        this.propertyRecommendations = propertyRecommendations;
    }

    public AnalyzedProperty getAnalyzedProperty() {
        return analyzedProperty;
    }

    public void setAnalyzedProperty(AnalyzedProperty analyzedProperty) {
        this.analyzedProperty = analyzedProperty;
    }

    @XmlElement(name = "propertyRecommendation")
    public List<PropertyRecommendation> getPropertyRecommendations() {
        return propertyRecommendations;
    }

    public void setPropertyRecommendations(List<PropertyRecommendation> propertyRecommendations) {
        this.propertyRecommendations = propertyRecommendations;
    }
    
    public PropertyRecommendation getPropertyRecommendation(TestResult result) {
        for(PropertyRecommendation r : propertyRecommendations) {
            if(r.getResult()== result) {
                return r;
            }
        }
        return new PropertyRecommendation(result, NO_INFORMATION_FOUND, NO_RECOMMENDATION_FOUND);
    }
}
