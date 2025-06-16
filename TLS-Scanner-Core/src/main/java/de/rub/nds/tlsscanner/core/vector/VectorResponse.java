/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector;

import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;

public class VectorResponse {

    private final ResponseFingerprint fingerprint;

    private final Vector vector;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private VectorResponse() {
        this.vector = null;
        this.fingerprint = null;
    }

    public VectorResponse(Vector vector, ResponseFingerprint fingerprint) {
        this.vector = vector;
        this.fingerprint = fingerprint;
    }

    public Vector getVector() {
        return vector;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    @Override
    public String toString() {
        return "VectorResponse{" + "fingerprint=" + fingerprint + ", vector=" + vector + '}';
    }
}
