/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.response;

/** A pair containing a response fingerprint and its associated secret value. */
public class FingerprintSecretPair {

    private final ResponseFingerprint fingerprint;
    private final int appliedSecret;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private FingerprintSecretPair() {
        fingerprint = null;
        appliedSecret = 0;
    }

    /**
     * Constructs a FingerprintSecretPair with the specified fingerprint and secret.
     *
     * @param fingerprint The response fingerprint
     * @param appliedSecret The secret value associated with this fingerprint
     */
    public FingerprintSecretPair(ResponseFingerprint fingerprint, int appliedSecret) {
        this.fingerprint = fingerprint;
        this.appliedSecret = appliedSecret;
    }

    /**
     * Gets the response fingerprint.
     *
     * @return The response fingerprint
     */
    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    /**
     * Gets the applied secret value.
     *
     * @return The applied secret value
     */
    public int getAppliedSecret() {
        return appliedSecret;
    }
}
