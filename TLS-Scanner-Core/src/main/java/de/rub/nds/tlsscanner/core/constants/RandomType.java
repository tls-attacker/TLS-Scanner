/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.constants;

/** Enum representing types of randomness you can encounter during and after TLS Handshakes. */
public enum RandomType {
    /** Initialization Vectors used in CBC Cipher suites. */
    CBC_IV("CBC IV"),
    /** Session IDs used for session resumption used in the ServerHello Message. */
    SESSION_ID("Session ID"),
    /** Random byte string to ensure unique TLS Handshakes used in the ServerHello Message. */
    RANDOM("Nonce (Random)"),
    /** Stateless cookie to prevent DoS attacks in DTLS. */
    COOKIE("Cookie");

    private String humanReadableName;

    private RandomType(String humanReadableName) {
        this.humanReadableName = humanReadableName;
    }

    public String getHumanReadableName() {
        return humanReadableName;
    }
}
