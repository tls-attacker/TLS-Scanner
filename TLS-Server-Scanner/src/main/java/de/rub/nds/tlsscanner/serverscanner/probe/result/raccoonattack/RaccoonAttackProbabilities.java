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

    /** Private no-arg constructor to please JAXB */
    @SuppressWarnings("unused")
    private RaccoonAttackProbabilities() {}

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

    public RaccoonAttackVulnerabilityPosition getPosition() {
        return position;
    }

    public void setPosition(RaccoonAttackVulnerabilityPosition position) {
        this.position = position;
    }

    public int getBitsLeaked() {
        return bitsLeaked;
    }

    public void setBitsLeaked(int bitsLeaked) {
        this.bitsLeaked = bitsLeaked;
    }

    public BigDecimal getChanceForEquation() {
        return chanceForEquation;
    }

    public void setChanceForEquation(BigDecimal chanceForEquation) {
        this.chanceForEquation = chanceForEquation;
    }

    public List<RaccoonAttackPskProbabilities> getPskProbabilityList() {
        return pskProbabilityList;
    }

    public void setPskProbabilityList(List<RaccoonAttackPskProbabilities> pskProbabilityList) {
        this.pskProbabilityList = pskProbabilityList;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }
}
