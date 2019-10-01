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
import java.util.LinkedHashMap;

public class ScoreReport {

    private final int score;

    private final LinkedHashMap<AnalyzedProperty, PropertyResultRatingInfluencer> influencers;

    public ScoreReport(int score, LinkedHashMap<AnalyzedProperty, PropertyResultRatingInfluencer> influencers) {
        this.score = score;
        this.influencers = influencers;
    }

    public int getScore() {
        return score;
    }

    public LinkedHashMap<AnalyzedProperty, PropertyResultRatingInfluencer> getInfluencers() {
        return influencers;
    }
}
