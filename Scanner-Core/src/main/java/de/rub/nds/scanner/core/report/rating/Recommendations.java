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
import java.io.Serializable;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Recommendations implements Serializable {

    @XmlElement(name = "recommendation")
    private List<Recommendation> recommendations;

    private Recommendations() {

    }

    public Recommendations(List<Recommendation> recommendations) {
        this.recommendations = recommendations;
    }

    public List<Recommendation> getRecommendations() {
        return recommendations;
    }

    public void setRecommendations(List<Recommendation> recommendations) {
        this.recommendations = recommendations;
    }

    public PropertyResultRecommendation getPropertyRecommendation(AnalyzedProperty property, TestResult result) {
        for (Recommendation r : recommendations) {
            if (r.getAnalyzedProperty() == property) {
                return r.getPropertyResultRecommendation(result);
            }
        }
        return new PropertyResultRecommendation(result, Recommendation.NO_RECOMMENDATION_FOUND,
            Recommendation.NO_RECOMMENDATION_FOUND);
    }

    public Recommendation getRecommendation(AnalyzedProperty property) {
        for (Recommendation r : recommendations) {
            if (r.getAnalyzedProperty() == property) {
                return r;
            }
        }
        return new Recommendation(property, property.toString());
    }
}
