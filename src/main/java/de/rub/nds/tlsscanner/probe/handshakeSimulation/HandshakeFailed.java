/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

public enum HandshakeFailed {
    PROTOCOL_MISMATCH("Client and server do not support a common tls protocol version"),
    CIPHERSUITE_MISMATCH("Client and server do not have a single ciphersuite in common"),
    PARSING_ERROR("Scanner could not parse all mandatory server messages"),
    CIPHERSUITE_FORBIDDEN("Client does not support forbidden ciphersuites for the selected protocol version"),
    PUBLIC_KEY_SIZE_RSA_NOT_ACCEPTED("Client does not support the rsa parameter size"),
    PUBLIC_KEY_SIZE_DH_NOT_ACCEPTED("Client does not support the dh parameter size"),
    UNKNOWN("Reason can not be specified");

    private final String reason;

    private HandshakeFailed(String reason) {
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }
}
