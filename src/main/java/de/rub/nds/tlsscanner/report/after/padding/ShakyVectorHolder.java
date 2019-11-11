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
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleCipherSuiteFingerprint;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.commons.math3.distribution.ChiSquaredDistribution;
import org.apache.commons.math3.stat.inference.ChiSquareTest;

/**
 *
 * @author ic0ns
 */
public class ShakyVectorHolder {

    private final PaddingOracleCipherSuiteFingerprint fingerprint;

    private final VectorContainer completeVectorHolder; //holds all vectors

    private final List<VectorContainer> statisticList;

    private final List<ResponseCounter> totalResponseCounterList;

    private final Set<String> shakyIdentifierSet;

    public ShakyVectorHolder(PaddingOracleCipherSuiteFingerprint fingerprint) {
        this.fingerprint = fingerprint;
        this.statisticList = new LinkedList<>();
        HashMap<String, List<VectorResponse>> vectorMap = new HashMap<>();
        List<VectorResponse> allVectorResponses = new LinkedList<>();
        for (List<VectorResponse> responseList : fingerprint.getResponseMapList()) {
            allVectorResponses.addAll(responseList);
            for (VectorResponse response : responseList) {
                if (vectorMap.containsKey(response.getPaddingVector().getIdentifier())) {
                    vectorMap.get(response.getPaddingVector().getIdentifier()).add(response);
                } else {
                    LinkedList<VectorResponse> tempResponseList = new LinkedList<>();
                    tempResponseList.add(response);
                    vectorMap.put(response.getPaddingVector().getIdentifier(), tempResponseList);
                }
            }
        }
        completeVectorHolder = new VectorContainer("ALL", allVectorResponses);

        shakyIdentifierSet = new HashSet<>();
        for (String identifier : vectorMap.keySet()) {
            VectorContainer vectorContainer = new VectorContainer(identifier, vectorMap.get(identifier));
            statisticList.add(vectorContainer);
            if (vectorContainer.getDistinctResponsesCounterList().size() > 1) {
                shakyIdentifierSet.add(identifier);
            }
        }
        totalResponseCounterList = completeVectorHolder.getDistinctResponsesCounterList();
    }

    public ShakyType getShakyType() {
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
            return ShakyType.MIXED;
        } else if (connectionBased) {
            return ShakyType.CONNECTION;
        } else {
            return ShakyType.HETEROGEN;
        }
    }

    public int getNumberOfShakyVectors() {
        return shakyIdentifierSet.size();
    }

    public PaddingOracleCipherSuiteFingerprint getFingerprint() {
        return fingerprint;
    }

    public List<VectorContainer> getStatisticList() {
        return Collections.unmodifiableList(statisticList);
    }

    public VectorContainer getCompleteVectorHolder() {
        return completeVectorHolder;
    }

    public Set<String> getShakyIdentifierSet() {
        return shakyIdentifierSet;
    }

    public boolean isAllVectorsShaky() {
        for (VectorContainer container : statisticList) {
            if (container.getDistinctResponsesCounterList().size() == 1) {
                return false;
            }
        }
        return true;
    }

    public double computePValue() {
        ChiSquareTest test = new ChiSquareTest();
        ResponseCounter defaultAnswer = null;
        for (ResponseCounter counter : totalResponseCounterList) {
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
            expected[i] = probability * getStatisticList().get(i).getResponseList().size();
            measured[i] = getStatisticList().get(i).getResponseCounterForFingerprint(defaultAnswer.getFingerprint()).getCounter();
        }
        double chiSquare = test.chiSquare(expected, measured);
        ChiSquaredDistribution distribution = new ChiSquaredDistribution(1);
        double pValue = 1 - distribution.cumulativeProbability(chiSquare);
        return pValue;
    }
}