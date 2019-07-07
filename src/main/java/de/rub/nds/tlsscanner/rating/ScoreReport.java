/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

import java.util.List;

public class ScoreReport {

    private final double score;

    private final List<Influencer> positiveInfluencerList;

    private final List<Influencer> negativeInfluencerList;

    public ScoreReport(double score, List<Influencer> positiveInfluencerList, List<Influencer> negativeInfluencerList) {
        this.score = score;
        this.positiveInfluencerList = positiveInfluencerList;
        this.negativeInfluencerList = negativeInfluencerList;
    }

    public double getScore() {
        return score;
    }

    public List<Influencer> getPositiveInfluencerList() {
        return positiveInfluencerList;
    }

    public List<Influencer> getNegativeInfluencerList() {
        return negativeInfluencerList;
    }
}
