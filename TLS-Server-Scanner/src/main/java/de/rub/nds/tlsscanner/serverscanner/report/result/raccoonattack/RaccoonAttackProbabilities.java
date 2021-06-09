/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.rub.nds.tlsscanner.serverscanner.report.result.raccoonattack;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.List;

public class RaccoonAttackProbabilities {

    private RaccoonAttackVulnerabilityPosition position;

    private int bitsLeaked;

    private BigDecimal chanceForEquation;

    private List<RaccoonAttackPskProbabilities> pskProbabilityList;

    private BigInteger modulus;

    private RaccoonAttackProbabilities() {
    }

    public RaccoonAttackProbabilities(RaccoonAttackVulnerabilityPosition position,
        int zeroBitsRequiredToNextBlockBorder, BigDecimal chanceForEquation,
        List<RaccoonAttackPskProbabilities> pskProbabilityList, BigInteger modulus) {
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
