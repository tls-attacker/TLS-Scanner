/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.constants;

import de.rub.nds.scanner.core.probe.ProbeType;

public enum QuicProbeType implements ProbeType {
    // SERVER SPECIFIC PROBES
    SUPPORTED_VERSIONS("Supported Versions"),
    TRANSPORT_PARAMETERS("Transport Parameters"),
    TLS12_HANDSHAKE("TLS 1.2 Handshake"),
    CONNECTION_MIGRATION("Connection Migration"),
    RETRY_PACKET("Retry Packet"),
    AFTER_HANDSHAKE("After Handhshake"),
    ANTI_DOS_LIMIT("Anti DoS Limit"),
    FRAGMENTATION("Fragmentation");

    @Override
    public String getName() {
        return humanReadableName;
    }

    private String humanReadableName;

    QuicProbeType(String humanReadableName) {
        this.humanReadableName = humanReadableName;
    }
}
