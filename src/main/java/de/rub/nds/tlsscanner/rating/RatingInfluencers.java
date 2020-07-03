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
import java.io.File;
import java.io.InputStream;
import java.io.Serializable;
import java.util.LinkedList;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "ratingInfluencers")
public class RatingInfluencers implements Serializable {

    /**
     * The default Config file to load.
     */
    static final String DEFAULT_RATING_FILE = "rating/influencers.xml";

    private LinkedList<RatingInfluencer> ratingInfluencers;

    private RatingInfluencers() {

    }

    public RatingInfluencers(LinkedList<RatingInfluencer> ratingInfluencers) {
        this.ratingInfluencers = ratingInfluencers;
    }

    public static RatingInfluencers createRatingInfluencers() {
        InputStream stream = RatingInfluencers.class.getResourceAsStream(DEFAULT_RATING_FILE);
        return RatingIO.readRatingInfluencers(stream);
    }

    public static RatingInfluencers createRatingInfluencers(File f) {
        return RatingIO.readRatingInfluencers(f);
    }

    public static RatingInfluencers createRatingInfluencers(InputStream stream) {
        return RatingIO.readRatingInfluencers(stream);
        // todo: close stream?
        // https://www.tutorialspoint.com/java/xml/javax_xml_bind_jaxb_unmarshal_inputstream
    }

    @XmlElement(name = "ratingInfluencer")
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
