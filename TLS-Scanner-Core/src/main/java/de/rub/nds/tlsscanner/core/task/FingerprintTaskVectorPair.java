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

/**
 * A pairing of a FingerPrintTask with its corresponding Vector. This class facilitates the
 * association between a fingerprinting task and the vector it processes.
 *
 * @param <VectorT> The type of vector, must extend Vector
 */
public class FingerprintTaskVectorPair<VectorT extends Vector> {

    private final FingerPrintTask fingerPrintTask;

    private final VectorT vector;

    /**
     * Constructs a new FingerprintTaskVectorPair with the specified task and vector.
     *
     * @param fingerPrintTask The fingerprinting task to associate with the vector
     * @param vector The vector to be processed by the fingerprinting task
     */
    public FingerprintTaskVectorPair(FingerPrintTask fingerPrintTask, VectorT vector) {
        this.fingerPrintTask = fingerPrintTask;
        this.vector = vector;
    }

    /**
     * Gets the fingerprinting task associated with this pair.
     *
     * @return The fingerprinting task
     */
    public FingerPrintTask getFingerPrintTask() {
        return fingerPrintTask;
    }

    /**
     * Gets the vector associated with this pair.
     *
     * @return The vector
     */
    public VectorT getVector() {
        return vector;
    }

    /**
     * Returns a string representation of this FingerprintTaskVectorPair.
     *
     * @return A string representation containing the task and vector
     */
    @Override
    public String toString() {
        return "FingerprintTaskVectorPair{"
                + "fingerPrintTask="
                + fingerPrintTask
                + ", vector="
                + vector
                + '}';
    }

    /**
     * Converts this pair into a VectorResponse by combining the vector with the fingerprint from
     * the task.
     *
     * @return A new VectorResponse containing the vector and its associated fingerprint
     */
    public VectorResponse toVectorResponse() {
        return new VectorResponse(vector, fingerPrintTask.getFingerprint());
    }
}
