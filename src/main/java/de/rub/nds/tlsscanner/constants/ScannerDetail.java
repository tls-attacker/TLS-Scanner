/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.constants;

/**
 *
 * @author robert
 */
public enum ScannerDetail implements Comparable<ScannerDetail> {
    ALL(100), DETAILED(75), NORMAL(50), QUICK(25);

    private int levelValue;

    private ScannerDetail(int levelValue) {
        this.levelValue = levelValue;
    }

    public int getLevelValue() {
        return levelValue;
    }

    public boolean isGreaterEqualTo(ScannerDetail detail) {
        return levelValue >= detail.getLevelValue();
    }
}
