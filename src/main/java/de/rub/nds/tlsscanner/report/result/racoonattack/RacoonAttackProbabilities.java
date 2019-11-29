/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result.racoonattack;

import java.util.List;

public class RacoonAttackProbabilities {

    private RacoonAttackVulnerabilityPosition position;

    private int zeroBytesRequiredToNextBlockBorder;

    private double chanceForEquation;

    private List<RacoonAttackPskProbabilities> pskProbabilityList;

    public RacoonAttackProbabilities(RacoonAttackVulnerabilityPosition position, int zeroBytesRequiredToNextBlockBorder, double chanceForEquation, List<RacoonAttackPskProbabilities> pskProbabilityList) {
        this.position = position;
        this.zeroBytesRequiredToNextBlockBorder = zeroBytesRequiredToNextBlockBorder;
        this.chanceForEquation = chanceForEquation;
        this.pskProbabilityList = pskProbabilityList;
    }

    public RacoonAttackVulnerabilityPosition getPosition() {
        return position;
    }

    public void setPosition(RacoonAttackVulnerabilityPosition position) {
        this.position = position;
    }

    public int getZeroBytesRequiredToNextBlockBorder() {
        return zeroBytesRequiredToNextBlockBorder;
    }

    public void setZeroBytesRequiredToNextBlockBorder(int zeroBytesRequiredToNextBlockBorder) {
        this.zeroBytesRequiredToNextBlockBorder = zeroBytesRequiredToNextBlockBorder;
    }

    public double getChanceForEquation() {
        return chanceForEquation;
    }

    public void setChanceForEquation(double chanceForEquation) {
        this.chanceForEquation = chanceForEquation;
    }

    public List<RacoonAttackPskProbabilities> getPskProbabilityList() {
        return pskProbabilityList;
    }

    public void setPskProbabilityList(List<RacoonAttackPskProbabilities> pskProbabilityList) {
        this.pskProbabilityList = pskProbabilityList;
    }

}
