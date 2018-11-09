/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

public enum HandshakeFailed {
    PROTOCOL_MISMATCH ("client and server do not speak the same tls protocol"),
    CIPHERSUITE_MISMATCH ("client and server do not have a single ciphersuite in common"),
    CIPHERSUITE_FORBIDDEN ("server sent forbidden ciphersuite which the client would not accept"),
    PUBLIC_KEY_LENGTH_NOT_ACCEPTED ("server sent a public key which the client would not accept because of its length"),
    UNKNOWN ("reason can not be specified");
    
    private final String reason;
    
    private HandshakeFailed(String reason) {    
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }
}