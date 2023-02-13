/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.constants;

public enum ScannerDetail implements Comparable<ScannerDetail> {
    ALL(100),
    DETAILED(75),
    NORMAL(50),
    QUICK(25);

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
