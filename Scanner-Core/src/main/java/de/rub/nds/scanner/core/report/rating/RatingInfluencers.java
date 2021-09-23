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
import java.util.LinkedList;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RatingInfluencers implements Serializable {

    @XmlElement(name = "ratingInfluencer")
    private LinkedList<RatingInfluencer> ratingInfluencers;

    private RatingInfluencers() {

    }

    public RatingInfluencers(LinkedList<RatingInfluencer> ratingInfluencers) {
        this.ratingInfluencers = ratingInfluencers;
    }

    public LinkedList<RatingInfluencer> getRatingInfluencers() {
        return ratingInfluencers;
    }

    public void setRatingInfluencers(LinkedList<RatingInfluencer> ratingInfluencers) {
        this.ratingInfluencers = ratingInfluencers;
    }

    public PropertyResultRatingInfluencer getPropertyRatingInfluencer(AnalyzedProperty property, TestResult result) {
        for (RatingInfluencer ri : ratingInfluencers) {
            if (ri.getAnalyzedProperty() == property) {
                return ri.getPropertyRatingInfluencer(result);
            }
        }
        return new PropertyResultRatingInfluencer(result, 0);
    }
}
