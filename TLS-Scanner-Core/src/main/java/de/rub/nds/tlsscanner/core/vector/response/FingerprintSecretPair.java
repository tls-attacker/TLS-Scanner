/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.response;

public class FingerprintSecretPair {

    private final ResponseFingerprint fingerprint;
    private final int appliedSecret;

    /** Private no-arg constructor to please JAXB */
    @SuppressWarnings("unused")
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
