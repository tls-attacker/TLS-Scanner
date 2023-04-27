/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.constants;

import de.rub.nds.scanner.core.constants.ProbeType;

public enum QuicProbeType implements ProbeType {
    SUPPORTED_VERSION("Supported Versions"),
    TRANSPORT_PARAMETERS("Transport Parameters"),
    TLS12_HANDSHAKE("TLS 1.2 Handshake"),
    CONNECTION_MIGRATION("Connection Migration");

    @Override
    public String getName() {
        return humanReadableName;
    }

    private String humanReadableName;

    QuicProbeType(String humanReadableName) {
        this.humanReadableName = humanReadableName;
    }
}
