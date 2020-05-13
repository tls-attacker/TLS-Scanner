/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.leak;

import de.rub.nds.tlsattacker.attacks.general.Vector;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class InformationLeakReport {

    private final List<InformationLeakTest> vectorHolderList;

    public InformationLeakReport(List<InformationLeakTest> vectorHolderList) {
        this.vectorHolderList = vectorHolderList;
    }

    public List<InformationLeakTest> getVectorHolderList() {
        return vectorHolderList;
    }

    public double distance(List<InformationLeakTest> otherVectorHolderList) {
        Set<Vector> vectorSet = new HashSet<>();
        for (InformationLeakTest thisHolder : vectorHolderList) {
            vectorSet.addAll(thisHolder.getAllVectors());
        }
        Set<Vector> otherVectorSet = new HashSet<>();
        for (InformationLeakTest otherHolder : otherVectorHolderList) {
            otherVectorSet.addAll(otherHolder.getAllVectors());
        }
        return 0;
    }
}
