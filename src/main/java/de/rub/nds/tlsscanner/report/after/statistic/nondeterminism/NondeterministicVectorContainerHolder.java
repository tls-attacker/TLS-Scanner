/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after.statistic.nondeterminism;

import de.rub.nds.tlsattacker.attacks.general.Vector;
import de.rub.nds.tlsscanner.report.after.statistic.ResponseCounter;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.util.FisherExactTest;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.commons.math3.distribution.ChiSquaredDistribution;
import org.apache.commons.math3.stat.inference.ChiSquareTest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NondeterministicVectorContainerHolder {

    private static final Logger LOGGER = LogManager.getLogger();

    private final List<VectorContainer> statisticList;

    public NondeterministicVectorContainerHolder(List<VectorResponse> responseList) {
        this.statisticList = new LinkedList<>();
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
            statisticList.add(new VectorContainer(vector, tempResponseList));
        }
    }

    public NondetermninismType getShakyType() {
        boolean connectionBased = false;
        boolean heterogen = false;
        for (VectorContainer container : statisticList) {
            if (container.areResponsesPlausibleConnectionBased()) {
                connectionBased = true;
            } else {
                heterogen = true;
            }
        }
        if (connectionBased && heterogen) {
            return NondetermninismType.MIXED;
        } else if (connectionBased) {
            return NondetermninismType.CONNECTION;
        } else {
            return NondetermninismType.HETEROGEN;
        }
    }

    public int getNumberOfShakyVectors() {
        int counter = 0;
        for (VectorContainer container : statisticList) {
            if (container.getDistinctResponsesCounterList().size() != 1) {
                counter++;
            }
        }
        return counter;
    }

    public List<VectorContainer> getStatisticList() {
        return Collections.unmodifiableList(statisticList);
    }

    public boolean isAllVectorsShaky() {
        for (VectorContainer container : statisticList) {
            if (container.getDistinctResponsesCounterList().size() == 1) {
                return false;
            }
        }
        return true;
    }

    private List<ResponseCounter> getAllResponseCounters() {
        List<ResponseFingerprint> fingerprintList = new LinkedList<>();
        for (VectorContainer container : statisticList) {
            fingerprintList.addAll(container.getResponseFingerprintList());
        }

        VectorContainer container = new VectorContainer(null, fingerprintList);
        return container.getDistinctResponsesCounterList();
    }

    public double computePValue() {

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
        VectorContainer container1 = statisticList.get(0);
        VectorContainer container2 = statisticList.get(1);
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
        ResponseCounter defaultAnswer = getDefaultAnswer();
        if (statisticList.size() < 2) {
            return 1;
        }
        double probability = defaultAnswer.getProbability();
        double[] expected = new double[statisticList.size()];
        long[] measured = new long[statisticList.size()];
        for (int i = 0; i < statisticList.size(); i++) {
            expected[i] = probability * statisticList.get(i).getResponseFingerprintList().size();
            measured[i] = statisticList.get(i).getResponseCounterForFingerprint(defaultAnswer.getFingerprint())
                    .getCounter();
        }
        double chiSquare = test.chiSquare(expected, measured);
        ChiSquaredDistribution distribution = new ChiSquaredDistribution(1);
        double pValue = 1 - distribution.cumulativeProbability(chiSquare);
        return pValue;

    }

    public ResponseCounter getDefaultAnswer() {
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

    private boolean isFisherExactUsable() {
        if (statisticList.size() != 2) {
            return false;
        }
        List<ResponseCounter> counterList1 = statisticList.get(0).getDistinctResponsesCounterList();
        List<ResponseCounter> counterList2 = statisticList.get(1).getDistinctResponsesCounterList();
        Set<ResponseFingerprint> responseFingerprintSet = new HashSet<>();
        for (ResponseCounter counter : counterList1) {
            responseFingerprintSet.add(counter.getFingerprint());
        }
        for (ResponseCounter counter : counterList2) {
            responseFingerprintSet.add(counter.getFingerprint());
        }
        return responseFingerprintSet.size() <= 2;
    }
}
