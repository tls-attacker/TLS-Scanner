/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.padding;

import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;

public class IdentifierResponse {

    private final String identifier;

    private final ResponseFingerprint fingerprint;

    public IdentifierResponse(String identifier, ResponseFingerprint fingerprint) {
        this.identifier = identifier;
        this.fingerprint = fingerprint;
    }

    public String getIdentifier() {
        return identifier;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }
}
