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
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAnyElement;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RatingInfluencer {

    @XmlAnyElement(lax = true)
    private AnalyzedProperty analyzedProperty;

    private List<PropertyResultRatingInfluencer> propertyRatingInfluencers;

    public RatingInfluencer() {
        this.propertyRatingInfluencers = new LinkedList<>();
    }

    public RatingInfluencer(AnalyzedProperty influencerConstant,
        List<PropertyResultRatingInfluencer> propertyRatingInfluencers) {
        this.analyzedProperty = influencerConstant;
        this.propertyRatingInfluencers = propertyRatingInfluencers;
    }

    public RatingInfluencer(AnalyzedProperty influencerConstant,
        PropertyResultRatingInfluencer... propertyRatingInfluencers) {
        this.analyzedProperty = influencerConstant;
        this.propertyRatingInfluencers = Arrays.asList(propertyRatingInfluencers);
    }

    public AnalyzedProperty getAnalyzedProperty() {
        return analyzedProperty;
    }

    public void setAnalyzedProperty(AnalyzedProperty analyzedProperty) {
        this.analyzedProperty = analyzedProperty;
    }

    public List<PropertyResultRatingInfluencer> getPropertyRatingInfluencers() {
        return propertyRatingInfluencers;
    }

    public void setPropertyRatingInfluencers(List<PropertyResultRatingInfluencer> propertyRatingInfluencers) {
        this.propertyRatingInfluencers = propertyRatingInfluencers;
    }

    public void addPropertyRatingInfluencer(PropertyResultRatingInfluencer ratingInfluence) {
        this.propertyRatingInfluencers.add(ratingInfluence);
    }

    public PropertyResultRatingInfluencer getPropertyRatingInfluencer(TestResult result) {
        for (PropertyResultRatingInfluencer ri : propertyRatingInfluencers) {
            if (ri.getResult() == result) {
                return ri;
            }
        }
        return new PropertyResultRatingInfluencer(result, 0);
    }
}
