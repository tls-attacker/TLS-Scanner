/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.task;

import de.rub.nds.tlsscanner.core.vector.Vector;
import de.rub.nds.tlsscanner.core.vector.VectorResponse;

public class FingerprintTaskVectorPair<VectorT extends Vector> {

    private final FingerPrintTask fingerPrintTask;

    private final VectorT vector;

    public FingerprintTaskVectorPair(FingerPrintTask fingerPrintTask, VectorT vector) {
        this.fingerPrintTask = fingerPrintTask;
        this.vector = vector;
    }

    public FingerPrintTask getFingerPrintTask() {
        return fingerPrintTask;
    }

    public VectorT getVector() {
        return vector;
    }

    @Override
    public String toString() {
        return "FingerprintTaskVectorPair{"
                + "fingerPrintTask="
                + fingerPrintTask
                + ", vector="
                + vector
                + '}';
    }

    public VectorResponse toVectorResponse() {
        return new VectorResponse(vector, fingerPrintTask.getFingerprint());
    }
}
