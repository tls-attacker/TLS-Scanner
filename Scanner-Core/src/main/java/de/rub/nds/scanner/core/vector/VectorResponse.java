/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.vector;

import de.rub.nds.scanner.core.vector.response.ResponseFingerprint;

public class VectorResponse {

    private final ResponseFingerprint fingerprint;

    private final Vector vector;

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
