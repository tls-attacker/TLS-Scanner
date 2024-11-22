/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.raccoonattack;

import java.math.BigDecimal;

public class RaccoonAttackPskProbabilities {

    private int pskLength;

    private int zeroBitsRequiredToNextBlockBorder;

    private BigDecimal chanceForEquation;

    /** Private no-arg constructor to please JAXB */
    @SuppressWarnings("unused")
    private RaccoonAttackPskProbabilities() {}

    public RaccoonAttackPskProbabilities(
            int pskLength, int zeroBitsRequiredToNextBlockBorder, BigDecimal chanceForEquation) {
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
