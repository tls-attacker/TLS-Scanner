/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after.statistic.padding;

import de.rub.nds.tlsattacker.attacks.general.Vector;
import de.rub.nds.tlsscanner.report.after.statistic.ResponseCounter;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class VectorContainer {

    private final Vector vector;

    private final List<ResponseCounter> distinctResponsesCounterList;

    private final List<ResponseFingerprint> responseList;

    public VectorContainer(Vector vector, List<ResponseFingerprint> responseFingerprintList) {
        this.vector = vector;
        this.distinctResponsesCounterList = new LinkedList<>();
        this.responseList = responseFingerprintList;
        HashSet<ResponseFingerprint> fingerprintSet = new HashSet<>();
        fingerprintSet.addAll(responseFingerprintList);
        for (ResponseFingerprint fingerprint : fingerprintSet) {
            int counter = 0;
            for (ResponseFingerprint tempFingerprint : responseFingerprintList) {
                if (Objects.equals(fingerprint, tempFingerprint)) {
                    counter++;
                }
            }
            distinctResponsesCounterList.add(new ResponseCounter(fingerprint, counter, responseFingerprintList.size()));
        }
    }

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

    public void addResponseFingerprint(ResponseFingerprint fingerprint) {
        responseList.add(fingerprint);
        boolean added = false;
        updateResponseCounter(fingerprint, added);
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
            ResponseCounter responseCounter = new ResponseCounter(fingerprint, 1, responseList.size());
            distinctResponsesCounterList.add(responseCounter);
            //We did not had this response yet 
        }
    }

    private int factorial(int n) {
        int solution = 1;
        for (int i = 1; i <= n; i++) {
            solution *= i;
        }
        return solution;
    }

    public List<ResponseCounter> getDistinctResponsesCounterList() {
        return Collections.unmodifiableList(distinctResponsesCounterList);
    }

    public List<ResponseFingerprint> getResponseFingerprintList() {
        return Collections.unmodifiableList(responseList);
    }

    public ResponseCounter getResponseCounterForFingerprint(ResponseFingerprint fingerprint) {
        for (ResponseCounter counter : distinctResponsesCounterList) {
            if (Objects.equals(counter.getFingerprint(), fingerprint)) {
                return counter;
            }
        }
        return new ResponseCounter(fingerprint, 0, responseList.size());
    }

    public Vector getVector() {
        return vector;
    }
}
