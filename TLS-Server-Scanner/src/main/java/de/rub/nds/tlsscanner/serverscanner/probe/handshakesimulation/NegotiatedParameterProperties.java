/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation;

public enum NegotiatedParameterProperties {
    FALSE_START,
    VULNERABLE_RENEGOTIATION_ATTACK,
    VULNERABLE_DOWNGRADE,
    VULNERABLE_SWEET32,
    VULNERABLE_POODLE,
    VULNERABLE_CRIME,
    VULNERABLE_PADDING_ORACLE,
    VULNERABLE_PASSIVE_BLEICHENBACHER,
    NOT_PERFECT_FORWARD_SECURE,
    PERFECT_FORWARD_SECURE,
    AUTHENTICATED_ENCRYPTION,
}
