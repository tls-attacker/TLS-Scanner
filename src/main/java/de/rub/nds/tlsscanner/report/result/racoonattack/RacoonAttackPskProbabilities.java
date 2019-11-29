package de.rub.nds.tlsscanner.report.result.racoonattack;

public class RacoonAttackPskProbabilities {

    private int pskLength;

    private int zeroBytesRequiredToNextBlockBorder;

    private double chanceForEquation;

    public RacoonAttackPskProbabilities(int pskLength, int zeroBytesRequiredToNextBlockBorder, double chanceForEquation) {
        this.pskLength = pskLength;
        this.zeroBytesRequiredToNextBlockBorder = zeroBytesRequiredToNextBlockBorder;
        this.chanceForEquation = chanceForEquation;
    }

    public int getPskLength() {
        return pskLength;
    }

    public void setPskLength(int pskLength) {
        this.pskLength = pskLength;
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

}
