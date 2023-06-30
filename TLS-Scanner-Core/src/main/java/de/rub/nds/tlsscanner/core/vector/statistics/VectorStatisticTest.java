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
import de.rub.nds.tlsscanner.core.vector.VectorResponse;
import de.rub.nds.tlsscanner.core.vector.response.EqualityError;
import de.rub.nds.tlsscanner.core.vector.response.FingerprintChecker;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class VectorStatisticTest<TestInfoT extends TestInfo> {

    protected static final double P_VALUE_SIGNIFICANCE_BORDER = 0.05;

    protected static final Logger LOGGER = LogManager.getLogger();

    protected final List<VectorContainer> vectorContainerList;

    protected final TestInfoT testInfo;

    protected double valueP;

    protected boolean distinctAnswers;

    protected boolean significantDistinctAnswers;

    public VectorStatisticTest(TestInfoT testInfo, List<VectorResponse> responseList) {
        this.testInfo = testInfo;
        vectorContainerList = new LinkedList<>();
        HashMap<Vector, List<ResponseFingerprint>> vectorMap = new HashMap<>();
        for (VectorResponse response : responseList) {
            if (vectorMap.containsKey(response.getVector())) {
                vectorMap.get(response.getVector()).add(response.getFingerprint());
            } else {
                LinkedList<ResponseFingerprint> tempResponseList = new LinkedList<>();
                tempResponseList.add(response.getFingerprint());
                vectorMap.put(response.getVector(), tempResponseList);
            }
        }
        for (Vector vector : vectorMap.keySet()) {
            List<ResponseFingerprint> tempResponseList = vectorMap.get(vector);
            vectorContainerList.add(new VectorContainer(vector, tempResponseList));
        }
    }

    public boolean isDistinctAnswers() {
        return distinctAnswers;
    }

    public boolean isSignificantDistinctAnswers() {
        return significantDistinctAnswers;
    }

    public double getValueP() {
        return valueP;
    }

    public TestInfoT getTestInfo() {
        return testInfo;
    }

    public List<VectorContainer> getVectorContainerList() {
        return vectorContainerList;
    }

    public VectorContainer getVectorContainer(Vector vector) {
        for (VectorContainer container : vectorContainerList) {
            if (container.getVector().equals(vector)) {
                return container;
            }
        }
        return null;
    }

    public Set<Vector> getAllVectors() {
        Set<Vector> vectorSet = new HashSet<>();
        for (VectorContainer vectorContainer : vectorContainerList) {
            vectorSet.add(vectorContainer.getVector());
        }
        return vectorSet;
    }

    public Set<ResponseFingerprint> getAllResponseFingerprints() {
        Set<ResponseFingerprint> responseSet = new HashSet<>();
        for (VectorContainer vectorContainer : vectorContainerList) {
            responseSet.addAll(vectorContainer.getResponseFingerprintList());
        }
        return responseSet;
    }

    private List<ResponseCounter> getAllResponseCounters() {
        List<ResponseFingerprint> fingerprintList = new LinkedList<>();
        for (VectorContainer container : vectorContainerList) {
            fingerprintList.addAll(container.getResponseFingerprintList());
        }

        VectorContainer container = new VectorContainer(null, fingerprintList);
        return container.getDistinctResponsesCounterList();
    }

    public ResponseCounter retrieveMostCommonAnswer() {
        ResponseCounter defaultAnswer = null;
        for (ResponseCounter counter : getAllResponseCounters()) {
            if (defaultAnswer == null) {
                defaultAnswer = counter;
            } else if (defaultAnswer.getCounter() < counter.getCounter()) {
                defaultAnswer = counter;
            }
        }
        return defaultAnswer;
    }

    public void extendTestWithVectorResponses(List<VectorResponse> vectorResponseList) {
        for (VectorResponse vectorResponse : vectorResponseList) {
            VectorContainer correctContainer = null;
            for (VectorContainer thisContainer : this.vectorContainerList) {
                if (thisContainer.getVector().equals(vectorResponse.getVector())) {
                    correctContainer = thisContainer;
                }
            }
            if (correctContainer != null) {
                correctContainer.addResponseFingerprint(vectorResponse.getFingerprint());
            } else {
                List<ResponseFingerprint> fingerprintList = new LinkedList<>();
                fingerprintList.add(vectorResponse.getFingerprint());
                vectorContainerList.add(
                        new VectorContainer(vectorResponse.getVector(), fingerprintList));
            }
        }
        updateInternals();
    }

    public void extendTestWithVectorContainers(List<VectorContainer> vectorContainerList) {
        for (VectorContainer otherContainer : vectorContainerList) {
            VectorContainer correctContainer = null;
            for (VectorContainer thisContainer : this.vectorContainerList) {
                if (thisContainer.getVector().equals(otherContainer.getVector())) {
                    correctContainer = thisContainer;
                }
            }
            if (correctContainer != null) {
                correctContainer.addResponseFingerprint(
                        otherContainer.getResponseFingerprintList());
            } else {
                this.vectorContainerList.add(otherContainer);
            }
        }
        updateInternals();
    }

    public EqualityError getEqualityError() {
        Set<ResponseFingerprint> fingerPrintSet = getAllResponseFingerprints();
        for (ResponseFingerprint fingerprint1 : fingerPrintSet) {
            for (ResponseFingerprint fingerprint2 : fingerPrintSet) {
                EqualityError equalityError =
                        FingerprintChecker.checkEquality(fingerprint1, fingerprint2);
                if (equalityError != EqualityError.NONE) {
                    return equalityError;
                }
            }
        }
        return EqualityError.NONE;
    }

    protected final void updateInternals() {
        valueP = computePValue();
        distinctAnswers = getAllResponseFingerprints().size() > 1;
        this.significantDistinctAnswers = valueP < P_VALUE_SIGNIFICANCE_BORDER;
    }

    private double computePValue() {
        if (isFisherExactUsable()) {
            LOGGER.debug("Computing P value based on fisher's exact test");
            double fisher = computePValueFisherExact();
            return fisher;
        } else {
            LOGGER.debug("Computing P value based on Chi² test");
            return computePValueChiSquared();
        }
    }

    abstract double computePValueFisherExact();

    abstract double computePValueChiSquared();

    abstract boolean isFisherExactUsable();
}
