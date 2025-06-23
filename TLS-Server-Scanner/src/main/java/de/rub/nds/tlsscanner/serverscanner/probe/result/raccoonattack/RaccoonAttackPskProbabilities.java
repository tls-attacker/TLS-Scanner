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

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private RaccoonAttackPskProbabilities() {}

    /**
     * Constructs a RaccoonAttackPskProbabilities instance with the specified parameters.
     *
     * @param pskLength the length of the pre-shared key
     * @param zeroBitsRequiredToNextBlockBorder the number of zero bits required to reach the next
     *     block border
     * @param chanceForEquation the probability/chance for the equation to hold
     */
    public RaccoonAttackPskProbabilities(
            int pskLength, int zeroBitsRequiredToNextBlockBorder, BigDecimal chanceForEquation) {
        this.pskLength = pskLength;
        this.zeroBitsRequiredToNextBlockBorder = zeroBitsRequiredToNextBlockBorder;
        this.chanceForEquation = chanceForEquation;
    }

    /**
     * Gets the PSK (pre-shared key) length.
     *
     * @return the length of the pre-shared key
     */
    public int getPskLength() {
        return pskLength;
    }

    /**
     * Sets the PSK (pre-shared key) length.
     *
     * @param pskLength the length of the pre-shared key to set
     */
    public void setPskLength(int pskLength) {
        this.pskLength = pskLength;
    }

    /**
     * Gets the number of zero bits required to reach the next block border.
     *
     * @return the number of zero bits required to next block border
     */
    public int getZeroBitsRequiredToNextBlockBorder() {
        return zeroBitsRequiredToNextBlockBorder;
    }

    /**
     * Sets the number of zero bits required to reach the next block border.
     *
     * @param zeroBitsRequiredToNextBlockBorder the number of zero bits required to set
     */
    public void setZeroBitsRequiredToNextBlockBorder(int zeroBitsRequiredToNextBlockBorder) {
        this.zeroBitsRequiredToNextBlockBorder = zeroBitsRequiredToNextBlockBorder;
    }

    /**
     * Gets the chance/probability for the equation.
     *
     * @return the chance for the equation as a BigDecimal
     */
    public BigDecimal getChanceForEquation() {
        return chanceForEquation;
    }

    /**
     * Sets the chance/probability for the equation.
     *
     * @param chanceForEquation the chance for the equation to set
     */
    public void setChanceForEquation(BigDecimal chanceForEquation) {
        this.chanceForEquation = chanceForEquation;
    }
}
