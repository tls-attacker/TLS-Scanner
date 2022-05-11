/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.vector.statistics;

import de.rub.nds.scanner.core.vector.Vector;
import de.rub.nds.scanner.core.vector.response.ResponseFingerprint;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class InformationLeakReport {

    private final List<InformationLeakTest> informationLeakList;

    public InformationLeakReport(List<InformationLeakTest> informationLeakList) {
        this.informationLeakList = informationLeakList;
    }

    public List<InformationLeakTest> getInformationLeakList() {
        return informationLeakList;
    }

    public double distance(List<InformationLeakTest> otherInformationLeakTestList) {
        Set<Vector> commonVectors = new HashSet<>();
        Set<ResponseFingerprint> commonFingerPrints = new HashSet<>();

        for (InformationLeakTest informationLeakTest : informationLeakList) {
            commonVectors.addAll(informationLeakTest.getAllVectors());
            commonFingerPrints.addAll(informationLeakTest.getAllResponseFingerprints());
        }
        Set<Vector> otherVectorSet = new HashSet<>();
        Set<ResponseFingerprint> otherFingerPrints = new HashSet<>();
        for (InformationLeakTest informationLeakTest : otherInformationLeakTestList) {
            otherVectorSet.addAll(informationLeakTest.getAllVectors());
            otherFingerPrints.addAll(informationLeakTest.getAllResponseFingerprints());
        }
        commonVectors.retainAll(otherVectorSet);
        commonFingerPrints.retainAll(otherFingerPrints);

        List<Double> measuredList = new ArrayList<>();
        List<Double> expectedList = new ArrayList<>();
        for (InformationLeakTest leakTest1 : informationLeakList) {
            for (InformationLeakTest leakTest2 : informationLeakList) {
                if (leakTest1.getTestInfo().equals(leakTest2.getTestInfo())) {
                    // we need to compare these
                    for (Vector vector : commonVectors) {
                        for (ResponseFingerprint responseFingerprint : commonFingerPrints) {
                            VectorContainer vectorContainer1 = leakTest1.getVectorContainer(vector);
                            measuredList.add(vectorContainer1.getResponseCounterForFingerprint(responseFingerprint)
                                .getProbability());
                            VectorContainer vectorContainer2 = leakTest2.getVectorContainer(vector);
                            expectedList.add(vectorContainer2.getResponseCounterForFingerprint(responseFingerprint)
                                .getProbability());
                        }
                    }
                    break;
                }
            }
        }

        double total = 0;
        for (int i = 0; i < measuredList.size(); i++) {
            double value = measuredList.get(i) - expectedList.get(i);
            value = value * value;
            total += value;
        }
        return total / measuredList.size();
    }
}
