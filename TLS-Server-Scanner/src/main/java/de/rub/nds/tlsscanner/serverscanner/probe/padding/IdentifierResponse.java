/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.padding;

import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;

/**
 *
 * @author ic0ns
 */
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
