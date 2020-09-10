/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.vectorStatistics;

import de.rub.nds.tlsattacker.attacks.general.Vector;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.serverscanner.leak.info.TestInfo;
import de.rub.nds.tlsscanner.serverscanner.util.FisherExactTest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.commons.math3.distribution.ChiSquaredDistribution;
import org.apache.commons.math3.stat.inference.ChiSquareTest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class InformationLeakTest<T extends TestInfo> {

    private static final double P_VALUE_SIGNIFICANCE_BORDER = 0.00001;

    private static final Logger LOGGER = LogManager.getLogger();

    private final List<VectorContainer> vectorContainerList;

    private final T testInfo;

    private double pValue;

    private boolean distinctAnswers;

    private boolean significantDistinctAnswers;

    public InformationLeakTest(T testInfo, List<VectorResponse> responseList) {
        this.testInfo = testInfo;
        this.vectorContainerList = new LinkedList<>();
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
        updateInternals();
    }

    private final void updateInternals() {
        pValue = computePValue();
        distinctAnswers = getAllResponseFingerprints().size() > 1;
        this.significantDistinctAnswers = pValue < P_VALUE_SIGNIFICANCE_BORDER;

    }

    public boolean isDistinctAnswers() {
        return distinctAnswers;
    }

    public boolean isSignificantDistinctAnswers() {
        return significantDistinctAnswers;
    }

    public double getpValue() {
        return pValue;
    }

    public T getTestInfo() {
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

    /**
     *
     * @return
     */
    private double computePValueFisherExact() {
        if (!isFisherExactUsable()) {
            throw new RuntimeException("Trying to use fisher exact test when it it not possible");
        }
        VectorContainer container1 = vectorContainerList.get(0);
        VectorContainer container2 = vectorContainerList.get(1);
        ResponseFingerprint responseA = null;
        ResponseFingerprint responseB = null;

        if (container1.getDistinctResponsesCounterList().size() > 1) {
            responseA = container1.getDistinctResponsesCounterList().get(0).getFingerprint();
            responseB = container1.getDistinctResponsesCounterList().get(1).getFingerprint();
        } else if (container2.getDistinctResponsesCounterList().size() > 1) {
            responseA = container2.getDistinctResponsesCounterList().get(0).getFingerprint();
            responseB = container2.getDistinctResponsesCounterList().get(1).getFingerprint();
        } else {
            responseA = container1.getDistinctResponsesCounterList().get(0).getFingerprint();
            responseB = container2.getDistinctResponsesCounterList().get(0).getFingerprint();
        }
        if (responseA.equals(responseB)) {
            // Both answers are identical
            return 1;
        }
        int input1ResponseA = 0;
        int input1ResponseB = 0;
        int input2ResponseA = 0;
        int input2ResponseB = 0;

        for (ResponseCounter counter : container1.getDistinctResponsesCounterList()) {
            if (counter.getFingerprint().equals(responseA)) {
                input1ResponseA = counter.getCounter();
            }
            if (counter.getFingerprint().equals(responseB)) {
                input1ResponseB = counter.getCounter();
            }
        }
        for (ResponseCounter counter : container2.getDistinctResponsesCounterList()) {
            if (counter.getFingerprint().equals(responseA)) {
                input2ResponseA = counter.getCounter();
            }
            if (counter.getFingerprint().equals(responseB)) {
                input2ResponseB = counter.getCounter();
            }
        }
        return FisherExactTest.getPValue(input1ResponseA, input2ResponseA, input1ResponseB, input2ResponseB);

    }

    private double computePValueChiSquared() {
        ChiSquareTest test = new ChiSquareTest();
        ResponseCounter defaultAnswer = retrieveMostCommonAnswer();
        if (vectorContainerList.size() < 2) {
            return 1;
        }
        double probability = defaultAnswer.getProbability();
        double[] expected = new double[vectorContainerList.size()];
        long[] measured = new long[vectorContainerList.size()];
        for (int i = 0; i < vectorContainerList.size(); i++) {
            expected[i] = probability * vectorContainerList.get(i).getResponseFingerprintList().size();
            measured[i] = vectorContainerList.get(i).getResponseCounterForFingerprint(defaultAnswer.getFingerprint())
                    .getCounter();
        }
        double chiSquare = test.chiSquare(expected, measured);
        ChiSquaredDistribution distribution = new ChiSquaredDistribution(1);
        double pValue = 1 - distribution.cumulativeProbability(chiSquare);
        return pValue;

    }

    private boolean isFisherExactUsable() {
        if (vectorContainerList.size() != 2) {
            return false;
        }
        List<ResponseCounter> counterList1 = vectorContainerList.get(0).getDistinctResponsesCounterList();
        List<ResponseCounter> counterList2 = vectorContainerList.get(1).getDistinctResponsesCounterList();
        Set<ResponseFingerprint> responseFingerprintSet = new HashSet<>();
        for (ResponseCounter counter : counterList1) {
            responseFingerprintSet.add(counter.getFingerprint());
        }
        for (ResponseCounter counter : counterList2) {
            responseFingerprintSet.add(counter.getFingerprint());
        }
        return responseFingerprintSet.size() <= 2;
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
                vectorContainerList.add(new VectorContainer(vectorResponse.getVector(), fingerprintList));
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
                correctContainer.addResponseFingerprint(otherContainer.getResponseFingerprintList());
            } else {
                vectorContainerList.add(new VectorContainer(otherContainer.getVector(), otherContainer
                        .getResponseFingerprintList()));
            }
        }
        updateInternals();
    }

    public EqualityError getEqualityError() {
        Set<ResponseFingerprint> fingerPrintSet = getAllResponseFingerprints();
        for (ResponseFingerprint fingerprint1 : fingerPrintSet) {
            for (ResponseFingerprint fingerprint2 : fingerPrintSet) {
                EqualityError equalityError = FingerPrintChecker.checkEquality(fingerprint1, fingerprint2);
                if (equalityError != EqualityError.NONE) {
                    return equalityError;
                }
            }
        }
        return EqualityError.NONE;
    }
}
