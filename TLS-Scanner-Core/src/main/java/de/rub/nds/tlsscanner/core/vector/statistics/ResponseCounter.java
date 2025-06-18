/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.statistics;

import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.concurrent.atomic.AtomicInteger;

public class ResponseCounter {

    private final ResponseFingerprint fingerprint;

    private final AtomicInteger counter;

    private final AtomicInteger total;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private ResponseCounter() {
        this.fingerprint = null;
        this.counter = new AtomicInteger(0);
        this.total = new AtomicInteger(0);
    }

    public ResponseCounter(ResponseFingerprint fingerprint, int counter, int total) {
        this.fingerprint = fingerprint;
        this.counter = new AtomicInteger(counter);
        this.total = new AtomicInteger(total);
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    public int getCounter() {
        return counter.get();
    }

    public int getTotal() {
        return total.get();
    }

    public void increaseCounterAndTotal() {
        counter.incrementAndGet();
        total.incrementAndGet();
    }

    public void increaseOnlyTotal() {
        total.incrementAndGet();
    }

    public double getProbability() {
        return (double) counter.get() / (double) total.get();
    }
}
