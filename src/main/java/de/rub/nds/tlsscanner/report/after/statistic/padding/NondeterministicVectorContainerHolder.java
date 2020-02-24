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
import de.rub.nds.tlsscanner.report.after.statistic.NondetermninismType;
import de.rub.nds.tlsscanner.report.after.statistic.ResponseCounter;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.math3.distribution.ChiSquaredDistribution;
import org.apache.commons.math3.stat.inference.ChiSquareTest;

/**
 *
 * @author ic0ns
 */
public class NondeterministicVectorContainerHolder {

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
        ChiSquareTest test = new ChiSquareTest();
        ResponseCounter defaultAnswer = null;
        for (ResponseCounter counter : getAllResponseCounters()) {
            if (defaultAnswer == null) {
                defaultAnswer = counter;
            } else if (defaultAnswer.getCounter() < counter.getCounter()) {
                defaultAnswer = counter;
            }
        }
        double probability = defaultAnswer.getProbability();
        double[] expected = new double[getStatisticList().size()];
        long[] measured = new long[getStatisticList().size()];
        for (int i = 0; i < getStatisticList().size(); i++) {
            expected[i] = probability * getStatisticList().get(i).getResponseFingerprintList().size();
            measured[i] = getStatisticList().get(i).getResponseCounterForFingerprint(defaultAnswer.getFingerprint()).getCounter();
        }
        double chiSquare = test.chiSquare(expected, measured);
        ChiSquaredDistribution distribution = new ChiSquaredDistribution(1);
        double pValue = 1 - distribution.cumulativeProbability(chiSquare);
        return pValue;
    }
}
