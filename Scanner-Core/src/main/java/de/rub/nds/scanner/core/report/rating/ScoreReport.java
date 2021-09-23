/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.report.rating;

import de.rub.nds.scanner.core.constants.AnalyzedProperty;
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
