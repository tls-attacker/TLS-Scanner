/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.handshakeSimulation;

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
