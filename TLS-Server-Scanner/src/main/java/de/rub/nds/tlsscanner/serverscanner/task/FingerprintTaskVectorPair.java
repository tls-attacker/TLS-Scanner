/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.task;

import de.rub.nds.tlsscanner.core.vector.Vector;
import de.rub.nds.tlsscanner.core.vector.VectorResponse;

public class FingerprintTaskVectorPair<T extends Vector> {

    private final FingerPrintTask fingerPrintTask;

    private final T vector;

    public FingerprintTaskVectorPair(FingerPrintTask fingerPrintTask, T vector) {
        this.fingerPrintTask = fingerPrintTask;
        this.vector = vector;
    }

    public FingerPrintTask getFingerPrintTask() {
        return fingerPrintTask;
    }

    public T getVector() {
        return vector;
    }

    @Override
    public String toString() {
        return "FingerprintTaskVectorPair{" + "fingerPrintTask=" + fingerPrintTask + ", vector=" + vector + '}';
    }

    public VectorResponse toVectorResponse() {
        return new VectorResponse(vector, fingerPrintTask.getFingerprint());
    }

}
