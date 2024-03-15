/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation;

public enum HandshakeFailureReasons {
    PROTOCOL_MISMATCH("Client and server do not support a common version"),
    CIPHER_SUITE_MISMATCH("Server does not have a valid cipher suite choice"),
    PARSING_ERROR("The answer received from the server was not parseable"),
    CIPHER_SUITE_FORBIDDEN("Client rejects cipher suite choice from the server"),
    RSA_CERTIFICATE_MODULUS_SIZE_NOT_ACCEPTED("Client does not support the RSA modulus size"),
    DHE_MODULUS_SIZE_NOT_ACCEPTED("Client does not support the DH parameter size"),
    ECDH_NO_COMMON_GROUP("Server does not have a group in common with the server"),
    NO_SNI("Client does not support SNI"),
    INVALID_SNI("Client supports SNI, but the Server does not like the provided hostname");

    private final String reason;

    private HandshakeFailureReasons(String reason) {
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }
}
