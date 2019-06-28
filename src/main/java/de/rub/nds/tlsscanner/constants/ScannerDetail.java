/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
