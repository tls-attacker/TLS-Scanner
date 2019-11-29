/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result.racoonattack;

import java.math.BigDecimal;

public class RacoonAttackPskProbabilities {

    private int pskLength;

    private int zeroBitsRequiredToNextBlockBorder;

    private BigDecimal chanceForEquation;

    public RacoonAttackPskProbabilities(int pskLength, int zeroBitsRequiredToNextBlockBorder, BigDecimal chanceForEquation) {
        this.pskLength = pskLength;
        this.zeroBitsRequiredToNextBlockBorder = zeroBitsRequiredToNextBlockBorder;
        this.chanceForEquation = chanceForEquation;
    }

    public int getPskLength() {
        return pskLength;
    }

    public void setPskLength(int pskLength) {
        this.pskLength = pskLength;
    }

    public int getZeroBitsRequiredToNextBlockBorder() {
        return zeroBitsRequiredToNextBlockBorder;
    }

    public void setZeroBitsRequiredToNextBlockBorder(int zeroBitsRequiredToNextBlockBorder) {
        this.zeroBitsRequiredToNextBlockBorder = zeroBitsRequiredToNextBlockBorder;
    }

    public BigDecimal getChanceForEquation() {
        return chanceForEquation;
    }

    public void setChanceForEquation(BigDecimal chanceForEquation) {
        this.chanceForEquation = chanceForEquation;
    }

}
