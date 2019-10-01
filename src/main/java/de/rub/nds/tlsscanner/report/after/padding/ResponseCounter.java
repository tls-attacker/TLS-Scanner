/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after.padding;

import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;

public class ResponseCounter {

    private final ResponseFingerprint fingerprint;

    private final int counter;

    private final int total;

    public ResponseCounter(ResponseFingerprint fingerprint, int counter, int total) {
        this.fingerprint = fingerprint;
        this.counter = counter;
        this.total = total;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    public int getCounter() {
        return counter;
    }

    public int getTotal() {
        return total;
    }

    public double getProbability() {
        return (double) counter / (double) total;
    }

}
