/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.statistics;

import de.rub.nds.tlsscanner.core.vector.Vector;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 * Container that holds a vector and its associated response fingerprints, tracking the occurrence
 * count of each distinct response and providing statistical analysis capabilities.
 */
public class VectorContainer {

    private final Vector vector;

    private final List<ResponseCounter> distinctResponsesCounterList;

    private final List<ResponseFingerprint> responseList;

    private final List<String> responseStringList;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private VectorContainer() {
        this.vector = null;
        this.distinctResponsesCounterList = new LinkedList<>();
        this.responseList = new LinkedList<>();
        this.responseStringList = new LinkedList<>();
    }

    /**
     * Creates a new vector container with the specified vector and response fingerprints.
     *
     * @param vector The vector associated with these responses
     * @param responseFingerprintList List of response fingerprints for this vector
     */
    public VectorContainer(Vector vector, List<ResponseFingerprint> responseFingerprintList) {
        this.vector = vector;
        this.distinctResponsesCounterList = new LinkedList<>();
        this.responseList = responseFingerprintList;
        this.responseStringList = new LinkedList<>();
        List<ResponseFingerprint> fingerprintSet = getUniqueFingerprints(responseFingerprintList);
        for (ResponseFingerprint fingerprint : fingerprintSet) {
            int counter = 0;
            for (ResponseFingerprint tempFingerprint : responseFingerprintList) {
                if (Objects.equals(fingerprint, tempFingerprint)) {
                    counter++;
                }
            }
            responseStringList.add(fingerprint.toHumanReadable());
            distinctResponsesCounterList.add(
                    new ResponseCounter(fingerprint, counter, responseFingerprintList.size()));
        }
    }

    /**
     * Checks whether all distinct responses in this container are plausibly connection-based by
     * verifying that all response fingerprints are compatible with each other.
     *
     * @return true if all responses are mutually compatible, false otherwise
     */
    public boolean areResponsesPlausibleConnectionBased() {
        for (ResponseCounter counterOne : distinctResponsesCounterList) {
            for (ResponseCounter counterTwo : distinctResponsesCounterList) {
                if (Objects.equals(counterOne.getFingerprint(), counterTwo.getFingerprint())) {
                    continue;
                }
                if (!counterOne.getFingerprint().areCompatible(counterTwo.getFingerprint())) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Calculates the probability of observing this specific response distribution assuming random
     * behavior.
     *
     * @param totalResponseCounterList List of response counters representing the total distribution
     * @return The calculated probability value
     */
    public double getRandomProbability(List<ResponseCounter> totalResponseCounterList) {
        double totalProbability = factorial(distinctResponsesCounterList.size());
        for (ResponseCounter counter : totalResponseCounterList) {
            for (ResponseCounter responseCounter : distinctResponsesCounterList) {
                if (Objects.equals(counter.getFingerprint(), responseCounter.getFingerprint())) {
                    totalProbability *= counter.getProbability();
                }
            }
        }
        return totalProbability;
    }

    /**
     * Adds multiple response fingerprints to this container.
     *
     * @param fingerprintList List of response fingerprints to add
     */
    public void addResponseFingerprint(List<ResponseFingerprint> fingerprintList) {
        for (ResponseFingerprint fingerPrint : fingerprintList) {
            addResponseFingerprint(fingerPrint);
        }
    }

    /**
     * Adds a single response fingerprint to this container and updates the response counters
     * accordingly.
     *
     * @param fingerprint The response fingerprint to add
     */
    public void addResponseFingerprint(ResponseFingerprint fingerprint) {
        responseList.add(fingerprint);
        responseStringList.add(fingerprint.toHumanReadable());
        updateResponseCounter(fingerprint, false);
    }

    private void updateResponseCounter(ResponseFingerprint fingerprint, boolean added) {
        for (ResponseCounter counter : distinctResponsesCounterList) {
            if (counter.getFingerprint().equals(fingerprint)) {
                added = true;
                counter.increaseCounterAndTotal();
            } else {
                counter.increaseOnlyTotal();
            }
        }
        if (!added) {
            ResponseCounter responseCounter =
                    new ResponseCounter(fingerprint, 1, responseList.size());
            distinctResponsesCounterList.add(responseCounter);
            // We did not had this response yet
        }
    }

    private int factorial(int n) {
        int solution = 1;
        for (int i = 1; i <= n; i++) {
            solution *= i;
        }
        return solution;
    }

    /**
     * Returns an unmodifiable list of response counters for all distinct responses.
     *
     * @return List of response counters for distinct responses
     */
    public List<ResponseCounter> getDistinctResponsesCounterList() {
        return Collections.unmodifiableList(distinctResponsesCounterList);
    }

    /**
     * Returns an unmodifiable list of all response fingerprints in this container.
     *
     * @return List of all response fingerprints
     */
    public List<ResponseFingerprint> getResponseFingerprintList() {
        return Collections.unmodifiableList(responseList);
    }

    /**
     * Returns the response counter for a specific fingerprint. If the fingerprint is not found,
     * returns a counter with zero occurrences.
     *
     * @param fingerprint The response fingerprint to look up
     * @return Response counter for the specified fingerprint
     */
    public ResponseCounter getResponseCounterForFingerprint(ResponseFingerprint fingerprint) {
        for (ResponseCounter counter : distinctResponsesCounterList) {
            if (Objects.equals(counter.getFingerprint(), fingerprint)) {
                return counter;
            }
        }
        return new ResponseCounter(fingerprint, 0, responseList.size());
    }

    /**
     * Returns the vector associated with this container.
     *
     * @return The vector
     */
    public Vector getVector() {
        return vector;
    }

    private List<ResponseFingerprint> getUniqueFingerprints(
            List<ResponseFingerprint> responseFingerprintList) {
        List<ResponseFingerprint> uniqueFps = new LinkedList<>();

        for (ResponseFingerprint fp : responseFingerprintList) {
            boolean alreadyListed = false;
            for (ResponseFingerprint ufp : uniqueFps) {
                if (Objects.equals(fp, ufp)) {
                    alreadyListed = true;
                }
            }

            if (!alreadyListed) {
                uniqueFps.add(fp);
            }
        }

        return uniqueFps;
    }
}
