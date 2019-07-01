/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.evaluation;

public class Influencer implements Comparable<Influencer> {

    private final InfluencerConstant influencerConstant;

    private final double positiveInfluence;

    private final double negativeInfluence;

    private final Double scoreCap;

    public Influencer(InfluencerConstant influencerConstant, double positiveInfluence, double negativeInfluence, Double scoreCap) {
        this.influencerConstant = influencerConstant;
        this.positiveInfluence = positiveInfluence;
        this.negativeInfluence = negativeInfluence;
        this.scoreCap = scoreCap;
    }

    public InfluencerConstant getInfluencerConstant() {
        return influencerConstant;
    }

    public double getPositiveInfluence() {
        return positiveInfluence;
    }

    public double getNegativeInfluence() {
        return negativeInfluence;
    }

    public Double getScoreCap() {
        return scoreCap;
    }

    @Override
    public int compareTo(Influencer t) {
        if (this.getScoreCap() != null && t.getScoreCap() == null) {
            return 1;
        }
        if (this.getScoreCap() == null && t.getScoreCap() != null) {
            return -1;
        }
        if (this.getScoreCap() != null && t.getScoreCap() != null) {
            Double.compare(this.getScoreCap(), t.getScoreCap());
        }
        int temp = Double.compare(this.getNegativeInfluence(), t.getNegativeInfluence());
        if (temp == 0) {
            return Double.compare(t.getPositiveInfluence(), this.getPositiveInfluence());
        }
        return temp;
    }

}
