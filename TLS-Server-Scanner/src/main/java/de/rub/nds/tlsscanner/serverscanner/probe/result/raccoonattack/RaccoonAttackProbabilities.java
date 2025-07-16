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
import java.math.BigInteger;
import java.util.List;

public class RaccoonAttackProbabilities {

    private RaccoonAttackVulnerabilityPosition position;

    private int bitsLeaked;

    private BigDecimal chanceForEquation;

    private List<RaccoonAttackPskProbabilities> pskProbabilityList;

    private BigInteger modulus;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private RaccoonAttackProbabilities() {}

    /**
     * Constructs a RaccoonAttackProbabilities instance with the specified parameters.
     *
     * @param position the vulnerability position in the Raccoon attack
     * @param zeroBitsRequiredToNextBlockBorder the number of zero bits required to reach the next
     *     block border
     * @param chanceForEquation the probability/chance for the equation to hold
     * @param pskProbabilityList list of PSK-specific probability calculations
     * @param modulus the modulus value used in calculations
     */
    public RaccoonAttackProbabilities(
            RaccoonAttackVulnerabilityPosition position,
            int zeroBitsRequiredToNextBlockBorder,
            BigDecimal chanceForEquation,
            List<RaccoonAttackPskProbabilities> pskProbabilityList,
            BigInteger modulus) {
        this.position = position;
        this.bitsLeaked = zeroBitsRequiredToNextBlockBorder;
        this.chanceForEquation = chanceForEquation;
        this.pskProbabilityList = pskProbabilityList;
        this.modulus = modulus;
    }

    /**
     * Gets the vulnerability position for the Raccoon attack.
     *
     * @return the vulnerability position
     */
    public RaccoonAttackVulnerabilityPosition getPosition() {
        return position;
    }

    /**
     * Sets the vulnerability position for the Raccoon attack.
     *
     * @param position the vulnerability position to set
     */
    public void setPosition(RaccoonAttackVulnerabilityPosition position) {
        this.position = position;
    }

    /**
     * Gets the number of bits leaked in the attack.
     *
     * @return the number of bits leaked
     */
    public int getBitsLeaked() {
        return bitsLeaked;
    }

    /**
     * Sets the number of bits leaked in the attack.
     *
     * @param bitsLeaked the number of bits leaked to set
     */
    public void setBitsLeaked(int bitsLeaked) {
        this.bitsLeaked = bitsLeaked;
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

    /**
     * Gets the list of PSK-specific probability calculations.
     *
     * @return the list of PSK probability calculations
     */
    public List<RaccoonAttackPskProbabilities> getPskProbabilityList() {
        return pskProbabilityList;
    }

    /**
     * Sets the list of PSK-specific probability calculations.
     *
     * @param pskProbabilityList the list of PSK probability calculations to set
     */
    public void setPskProbabilityList(List<RaccoonAttackPskProbabilities> pskProbabilityList) {
        this.pskProbabilityList = pskProbabilityList;
    }

    /**
     * Gets the modulus value used in calculations.
     *
     * @return the modulus value
     */
    public BigInteger getModulus() {
        return modulus;
    }

    /**
     * Sets the modulus value used in calculations.
     *
     * @param modulus the modulus value to set
     */
    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }
}
