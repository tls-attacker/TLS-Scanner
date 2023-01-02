/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.constant;

public enum CruxListNumber {
    TOP_1k(1000),
    TOP_5K(5000),
    TOP_10K(10000),
    TOP_50K(50000),
    TOP_100K(100000),
    TOP_500k(500000),
    TOP_1M(1000000);

    private final int number;

    CruxListNumber(int number) {
        this.number = number;
    }

    public int getNumber() {
        return number;
    }
}
