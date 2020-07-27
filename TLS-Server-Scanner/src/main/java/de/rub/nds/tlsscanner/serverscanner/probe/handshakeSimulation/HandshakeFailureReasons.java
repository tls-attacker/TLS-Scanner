/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

public enum HandshakeFailureReasons {
    PROTOCOL_MISMATCH("Client and server do not support a common version"),
    CIPHERSUITE_MISMATCH("Server does not have a valid ciphersuite choice"),
    PARSING_ERROR("The answer received from the server was not parseable"),
    CIPHERSUITE_FORBIDDEN("Client rejects ciphersuite choice from the server"),
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
