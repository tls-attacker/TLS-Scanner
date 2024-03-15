/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.handshakesimulation;

public enum ConnectionInsecure {
    CIPHER_SUITE_GRADE_LOW("Grade of the selected cipher suite is low"),
    PUBLIC_KEY_SIZE_TOO_SMALL(
            "Server public key parameter is too small (ECRYPT-CSA recommendations 2018)"),
    PADDING_ORACLE("Connection is vulnerable to padding oracle"),
    BLEICHENBACHER("Connection is vulnerable to bleichenbacher"),
    CRIME("Connection is vulnerable to crime"),
    SWEET32("Connection is vulnerable to sweet32");

    private final String reason;

    private ConnectionInsecure(String reason) {
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }
}
