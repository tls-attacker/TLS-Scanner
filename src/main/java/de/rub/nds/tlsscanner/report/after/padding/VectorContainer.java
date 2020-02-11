/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after.padding;

import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class VectorContainer {

    private final String identifier;

    private final List<ResponseCounter> distinctResponsesCounterList;

    private final List<VectorResponse> responseList;

    public VectorContainer(String identifier, List<VectorResponse> responseList) {
        this.identifier = identifier;
        this.distinctResponsesCounterList = new LinkedList<>();
        this.responseList = responseList;
        HashSet<ResponseFingerprint> fingerprintSet = new HashSet<>();
        for (VectorResponse vectorResponse : responseList) {
            if (!fingerprintSet.contains(vectorResponse.getFingerprint())) {
                fingerprintSet.add(vectorResponse.getFingerprint());
            }
        }
        for (ResponseFingerprint fingerprint : fingerprintSet) {
            int counter = 0;
            for (VectorResponse response : responseList) {
                if (Objects.equals(response.getFingerprint(), fingerprint)) {
                    counter++;
                }
            }
            distinctResponsesCounterList.add(new ResponseCounter(fingerprint, counter, responseList.size()));
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
        int total = responseList.size();
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

    private int factorial(int n) {
        int solution = 1;
        for (int i = 1; i <= n; i++) {
            solution *= i;
        }
        return solution;
    }

    public String getIdentifier() {
        return identifier;
    }

    public List<ResponseCounter> getDistinctResponsesCounterList() {
        return Collections.unmodifiableList(distinctResponsesCounterList);
    }

    public List<VectorResponse> getResponseList() {
        return Collections.unmodifiableList(responseList);
    }

    public ResponseCounter getResponseCounterForFingerprint(ResponseFingerprint fingerprint) {
        for (ResponseCounter counter : distinctResponsesCounterList) {
            if (Objects.equals(counter.getFingerprint(), fingerprint)) {
                return counter;
            }
        }
        return null;
    }
}
