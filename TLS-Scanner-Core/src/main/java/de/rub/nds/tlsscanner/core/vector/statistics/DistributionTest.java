/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.statistics;

import de.rub.nds.tlsscanner.core.vector.VectorResponse;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.math3.distribution.ChiSquaredDistribution;
import org.apache.commons.math3.stat.inference.ChiSquareTest;

public class DistributionTest<TestInfoT extends TestInfo> extends VectorStatisticTest<TestInfoT> {

    private final double probability;

    public DistributionTest(
            TestInfoT testInfo, List<VectorResponse> responseList, double probability) {
        super(testInfo, responseList);
        if (vectorContainerList.size() != 1) {
            throw new RuntimeException("DistributionTest expects exactly one VectorContainer");
        }
        this.probability = probability;
        updateInternals();
    }

    @Override
    protected double computePValueFisherExact() {
        int expectedB =
                (int)
                        (probability
                                * vectorContainerList.get(0).getResponseFingerprintList().size());
        int expectedA = vectorContainerList.get(0).getResponseFingerprintList().size() - expectedB;
        if (!isFisherExactUsable()) {
            throw new RuntimeException("Trying to use fisher exact test when it is not possible");
        }
        List<ResponseCounter> responseCounters =
                vectorContainerList.get(0).getDistinctResponsesCounterList();
        int responseA;
        int responseB;

        if (responseCounters.get(0).getCounter() > responseCounters.get(1).getCounter()) {
            responseA = responseCounters.get(0).getCounter();
            responseB = responseCounters.get(1).getCounter();
        } else {
            responseA = responseCounters.get(1).getCounter();
            responseB = responseCounters.get(0).getCounter();
        }
        return FisherExactTest.getPValue(responseA, responseB, expectedA, expectedB);
    }

    @Override
    protected double computePValueChiSquared() {
        int expectedB =
                (int)
                        (probability
                                * vectorContainerList.get(0).getResponseFingerprintList().size());
        int expectedA = vectorContainerList.get(0).getResponseFingerprintList().size() - expectedB;
        ChiSquareTest test = new ChiSquareTest();

        if (vectorContainerList.get(0).getDistinctResponsesCounterList().size() < 2) {
            return 1;
        }
        List<ResponseCounter> sortedMeasured = getSortedDistinctResponseCounters();
        long[] expected = new long[sortedMeasured.size()];
        long[] measured = new long[sortedMeasured.size()];
        for (int i = 0;
                i < vectorContainerList.get(0).getDistinctResponsesCounterList().size();
                i++) {
            if (i == 0) {
                expected[i] = expectedA;
            } else if (i == 1) {
                expected[i] = expectedB;
            }
            measured[i] = sortedMeasured.get(i).getCounter();
        }
        double chiSquare = test.chiSquareDataSetsComparison(expected, measured);
        ChiSquaredDistribution distribution = new ChiSquaredDistribution(1);
        double valueP = 1 - distribution.cumulativeProbability(chiSquare);
        return valueP;
    }

    @Override
    protected boolean isFisherExactUsable() {
        return vectorContainerList.get(0).getDistinctResponsesCounterList().size() == 2;
    }

    private List<ResponseCounter> getSortedDistinctResponseCounters() {
        List<ResponseCounter> unsorted =
                vectorContainerList.get(0).getDistinctResponsesCounterList();
        List<ResponseCounter> sorted = new LinkedList<>();
        ResponseCounter highestCounter = null;
        for (int i = 0; i < unsorted.size(); i++) {
            for (ResponseCounter toCompare : unsorted) {
                if (!sorted.contains(toCompare)
                        && (highestCounter == null
                                || highestCounter.getCounter() < toCompare.getCounter())) {
                    highestCounter = toCompare;
                }
            }
            sorted.add(highestCounter);
            highestCounter = null;
        }

        return sorted;
    }
}
