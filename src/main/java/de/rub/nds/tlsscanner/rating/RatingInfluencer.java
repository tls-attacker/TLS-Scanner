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

public class RatingInfluencer {

    private AnalyzedProperty analyzedProperty;
    
    private List<PropertyRatingInfluencer> propertyRatingInfluencers;

    public RatingInfluencer() {
        this.propertyRatingInfluencers = new LinkedList<>();
    }

    public RatingInfluencer(AnalyzedProperty influencerConstant, List<PropertyRatingInfluencer> propertyRatingInfluencers) {
        this.analyzedProperty = influencerConstant;
        this.propertyRatingInfluencers = propertyRatingInfluencers;
    }

    public AnalyzedProperty getAnalyzedProperty() {
        return analyzedProperty;
    }

    public void setAnalyzedProperty(AnalyzedProperty analyzedProperty) {
        this.analyzedProperty = analyzedProperty;
    }
    
    @XmlElement(name = "propertyRatingInfluencer")
    public List<PropertyRatingInfluencer> getPropertyRatingInfluencers() {
        return propertyRatingInfluencers;
    }

    public void setPropertyRatingInfluencers(List<PropertyRatingInfluencer> propertyRatingInfluencers) {
        this.propertyRatingInfluencers = propertyRatingInfluencers;
    }
    
    public void addPropertyRatingInfluencer(PropertyRatingInfluencer ratingInfluence) {
        this.propertyRatingInfluencers.add(ratingInfluence);
    }
    
    public PropertyRatingInfluencer getPropertyRatingInfluencer(TestResult result) {
        for(PropertyRatingInfluencer ri : propertyRatingInfluencers) {
            if(ri.getResult() == result) {
                return ri;
            }
        }
        return new PropertyRatingInfluencer(result, 0);
    }
}
