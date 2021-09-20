/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.rating;

import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.LinkedHashMap;

public class ScoreReport {

    private final int score;

    private final LinkedHashMap<TlsAnalyzedProperty, PropertyResultRatingInfluencer> influencers;

    public ScoreReport(int score, LinkedHashMap<TlsAnalyzedProperty, PropertyResultRatingInfluencer> influencers) {
        this.score = score;
        this.influencers = influencers;
    }

    public int getScore() {
        return score;
    }

    public LinkedHashMap<TlsAnalyzedProperty, PropertyResultRatingInfluencer> getInfluencers() {
        return influencers;
    }
}
