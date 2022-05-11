/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.vector.response;

public class FingerprintSecretPair {

    private final ResponseFingerprint fingerprint;
    private final int appliedSecret;

    private FingerprintSecretPair() {
        fingerprint = null;
        appliedSecret = 0;
    }

    public FingerprintSecretPair(ResponseFingerprint fingerprint, int appliedSecret) {
        this.fingerprint = fingerprint;
        this.appliedSecret = appliedSecret;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    public int getAppliedSecret() {
        return appliedSecret;
    }
}
