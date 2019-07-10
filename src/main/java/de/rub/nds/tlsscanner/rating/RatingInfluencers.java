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

@XmlRootElement(name="ratingInfluencers")
public class RatingInfluencers implements Serializable {
    
    private List<RatingInfluencer> ratingInfluencers;

    @XmlElement(name = "ratingInfluencer")
    public List<RatingInfluencer> getRatingInfluencers() {
        return ratingInfluencers;
    }

    public void setRatingInfluencers(List<RatingInfluencer> ratingInfluencers) {
        this.ratingInfluencers = ratingInfluencers;
    }
    
    public PropertyRatingInfluencer getPropertyRatingInfluencer(AnalyzedProperty property, TestResult result) {
        for (RatingInfluencer ri : ratingInfluencers) {
            if(ri.getAnalyzedProperty() == property) {
                return ri.getPropertyRatingInfluencer(result);
            }
        }
        return new PropertyRatingInfluencer(result, 0.0);
    }
}