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

/**
 * Tracks the occurrence count of a specific response fingerprint and calculates its probability
 * within the total set of responses. This class is thread-safe for concurrent counting operations.
 */
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

    /**
     * Creates a new response counter with initial values.
     *
     * @param fingerprint The response fingerprint to track
     * @param counter Initial count of occurrences for this fingerprint
     * @param total Initial total count of all responses
     */
    public ResponseCounter(ResponseFingerprint fingerprint, int counter, int total) {
        this.fingerprint = fingerprint;
        this.counter = new AtomicInteger(counter);
        this.total = new AtomicInteger(total);
    }

    /**
     * Returns the response fingerprint being tracked.
     *
     * @return The response fingerprint
     */
    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    /**
     * Returns the current count of occurrences for this fingerprint.
     *
     * @return The occurrence count
     */
    public int getCounter() {
        return counter.get();
    }

    /**
     * Returns the total count of all responses.
     *
     * @return The total response count
     */
    public int getTotal() {
        return total.get();
    }

    /**
     * Increments both the occurrence counter and the total counter by one. This method is
     * thread-safe.
     */
    public void increaseCounterAndTotal() {
        counter.incrementAndGet();
        total.incrementAndGet();
    }

    /**
     * Increments only the total counter by one, leaving the occurrence counter unchanged. This
     * method is thread-safe.
     */
    public void increaseOnlyTotal() {
        total.incrementAndGet();
    }

    /**
     * Calculates the probability of this response fingerprint based on its occurrence count
     * relative to the total.
     *
     * @return The probability as a value between 0.0 and 1.0
     */
    public double getProbability() {
        return (double) counter.get() / (double) total.get();
    }
}
