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
import java.io.Serializable;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name="recommendations")
public class Recommendations implements Serializable {
    
    private List<Recommendation> recommendations;

    @XmlElement(name = "recommendation")
    public List<Recommendation> getRecommendations() {
        return recommendations;
    }

    public void setRecommendations(List<Recommendation> recommendations) {
        this.recommendations = recommendations;
    }
    
    public PropertyRecommendation getPropertyRecommendation(AnalyzedProperty property, TestResult result) {
        for(Recommendation pr : recommendations) {
            if(pr.getAnalyzedProperty() == property) {
                return pr.getPropertyRecommendation(result);
            }
        }
        return new PropertyRecommendation(result, Recommendation.NO_RECOMMENDATION_FOUND, 
                Recommendation.NO_RECOMMENDATION_FOUND);
    }
    
}
