/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

public enum HandshakeFailed {
    PROTOCOL_MISMATCH ("client and server do not speak the same tls protocol"),
    CIPHERSUITE_MISMATCH ("client and server do not have a single ciphersuite in common"),
    CIPHERSUITE_FORBIDDEN ("client does not support forbidden ciphersuites for the selected protocol version"),
    PUBLIC_KEY_LENGTH_RSA_NOT_ACCEPTED ("client does not support the length of the rsa public key of the server"),
    PUBLIC_KEY_LENGTH_DH_NOT_ACCEPTED ("client does not support the length of the dh public key of the server"),
    UNKNOWN ("reason can not be specified");
    
    private final String reason;
    
    private HandshakeFailed(String reason) {    
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }
}