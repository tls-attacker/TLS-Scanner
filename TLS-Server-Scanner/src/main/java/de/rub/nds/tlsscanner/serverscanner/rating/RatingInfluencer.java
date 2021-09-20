/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.rating;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;

public class RatingInfluencer {

    private TlsAnalyzedProperty analyzedProperty;

    private List<PropertyResultRatingInfluencer> propertyRatingInfluencers;

    public RatingInfluencer() {
        this.propertyRatingInfluencers = new LinkedList<>();
    }

    public RatingInfluencer(TlsAnalyzedProperty influencerConstant,
        List<PropertyResultRatingInfluencer> propertyRatingInfluencers) {
        this.analyzedProperty = influencerConstant;
        this.propertyRatingInfluencers = propertyRatingInfluencers;
    }

    public RatingInfluencer(TlsAnalyzedProperty influencerConstant,
        PropertyResultRatingInfluencer... propertyRatingInfluencers) {
        this.analyzedProperty = influencerConstant;
        this.propertyRatingInfluencers = Arrays.asList(propertyRatingInfluencers);
    }

    public TlsAnalyzedProperty getAnalyzedProperty() {
        return analyzedProperty;
    }

    public void setAnalyzedProperty(TlsAnalyzedProperty analyzedProperty) {
        this.analyzedProperty = analyzedProperty;
    }

    @XmlElement(name = "propertyResultRatingInfluencer")
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
