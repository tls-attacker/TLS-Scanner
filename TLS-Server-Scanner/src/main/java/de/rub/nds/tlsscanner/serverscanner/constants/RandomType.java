/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.constants;

/**
 * Enum representing types of randomness you can encounter during and after TLS Handshakes.
 */
public enum RandomType {
    // Initialization Vectors used in CBC Cipher suites.
    IV,
    // Session IDs used for session resumption used in the ServerHello Message
    SESSION_ID,
    // Random byte string to ensure unique TLS Handshakes used in the
    // ServerHello Message
    RANDOM,
    // Complete Sequence consisting of concatenated Randoms, Session IDs and
    // IVs.
    COMPLETE_SEQUENCE
}
