/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
