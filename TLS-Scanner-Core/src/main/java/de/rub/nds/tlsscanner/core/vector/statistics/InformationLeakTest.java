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
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.commons.math3.distribution.ChiSquaredDistribution;
import org.apache.commons.math3.stat.inference.ChiSquareTest;

public class InformationLeakTest<TestInfoT extends TestInfo>
        extends VectorStatisticTest<TestInfoT> {

    public InformationLeakTest(TestInfoT testInfo, List<VectorResponse> responseList) {
        super(testInfo, responseList);
        updateInternals();
    }

    /**
     * @return
     */
    @Override
    protected double computePValueFisherExact() {
        if (!isFisherExactUsable()) {
            throw new RuntimeException("Trying to use fisher exact test when it is not possible");
        }
        VectorContainer container1 = getVectorContainerList().get(0);
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
        return FisherExactTest.getPValue(
                input1ResponseA, input2ResponseA, input1ResponseB, input2ResponseB);
    }

    @Override
    protected double computePValueChiSquared() {
        ChiSquareTest test = new ChiSquareTest();
        ResponseCounter defaultAnswer = retrieveMostCommonAnswer();
        if (vectorContainerList.size() < 2) {
            return 1;
        }
        double probability = defaultAnswer.getProbability();
        double[] expected = new double[vectorContainerList.size()];
        long[] measured = new long[vectorContainerList.size()];
        for (int i = 0; i < vectorContainerList.size(); i++) {
            expected[i] =
                    probability * vectorContainerList.get(i).getResponseFingerprintList().size();
            measured[i] =
                    vectorContainerList
                            .get(i)
                            .getResponseCounterForFingerprint(defaultAnswer.getFingerprint())
                            .getCounter();
        }
        double chiSquare = test.chiSquare(expected, measured);
        ChiSquaredDistribution distribution = new ChiSquaredDistribution(1);
        double valueP = 1 - distribution.cumulativeProbability(chiSquare);
        return valueP;
    }

    @Override
    protected boolean isFisherExactUsable() {
        if (vectorContainerList.size() != 2) {
            return false;
        }
        List<ResponseCounter> counterList1 =
                vectorContainerList.get(0).getDistinctResponsesCounterList();
        List<ResponseCounter> counterList2 =
                vectorContainerList.get(1).getDistinctResponsesCounterList();
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
