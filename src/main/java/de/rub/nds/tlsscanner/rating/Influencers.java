/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

import java.io.Serializable;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name="ratingInfluencers")
public class Influencers implements Serializable {
    
    private List<Influencer> influencers;

    @XmlElement(name = "ratingInfluencer")
    public List<Influencer> getInfluencers() {
        return influencers;
    }

    public void setInfluencers(List<Influencer> influencers) {
        this.influencers = influencers;
    }
}