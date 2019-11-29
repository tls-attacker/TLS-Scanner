/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result.racoonattack;

import java.math.BigDecimal;
import java.util.List;

public class RacoonAttackProbabilities {

    private RacoonAttackVulnerabilityPosition position;

    private int zeroBitsRequiredToNextBlockBorder;

    private BigDecimal chanceForEquation;

    private List<RacoonAttackPskProbabilities> pskProbabilityList;

    public RacoonAttackProbabilities(RacoonAttackVulnerabilityPosition position, int zeroBitsRequiredToNextBlockBorder, BigDecimal chanceForEquation, List<RacoonAttackPskProbabilities> pskProbabilityList) {
        this.position = position;
        this.zeroBitsRequiredToNextBlockBorder = zeroBitsRequiredToNextBlockBorder;
        this.chanceForEquation = chanceForEquation;
        this.pskProbabilityList = pskProbabilityList;
    }

    public RacoonAttackVulnerabilityPosition getPosition() {
        return position;
    }

    public void setPosition(RacoonAttackVulnerabilityPosition position) {
        this.position = position;
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

    public List<RacoonAttackPskProbabilities> getPskProbabilityList() {
        return pskProbabilityList;
    }

    public void setPskProbabilityList(List<RacoonAttackPskProbabilities> pskProbabilityList) {
        this.pskProbabilityList = pskProbabilityList;
    }

}
