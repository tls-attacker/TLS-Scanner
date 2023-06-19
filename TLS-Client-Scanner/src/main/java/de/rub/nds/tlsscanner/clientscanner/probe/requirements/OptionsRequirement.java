/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

/** Represents a {@link Requirement} for additional, optional flags in commands. */
public class OptionsRequirement extends Requirement<ClientReport> {

    private final ClientScannerConfig scannerConfig;

    /* ProbeType of the respective option. */
    private final TlsProbeType type;

    /* domain for sni option (optional). */
    private final String domain;

    /**
     * @param scannerConfig the {@link ClientScannerConfig}.
     * @param type the {@link TlsProbeType} of the option.
     */
    public OptionsRequirement(ClientScannerConfig scannerConfig, TlsProbeType type) {
        this.scannerConfig = scannerConfig;
        this.type = type;
        this.domain = null;
    }

    /**
     * @param scannerConfig the {@link ClientScannerConfig}.
     * @param type the {@link TlsProbeType} of the option.
     * @param domain the domain for the sni option.
     */
    public OptionsRequirement(ClientScannerConfig scannerConfig, TlsProbeType type, String domain) {
        this.scannerConfig = scannerConfig;
        this.type = type;
        this.domain = domain;
    }

    @Override
    public boolean evaluate(ClientReport report) {
        if (scannerConfig == null || type == null) {
            return false;
        }
        switch (type) {
            case ALPN:
                return scannerConfig.getClientParameterDelegate().getAlpnOptions() != null;
            case SNI:
                return domain != null
                        && scannerConfig.getClientParameterDelegate().getSniOptions(domain) != null;
            case RESUMPTION:
                return scannerConfig.getClientParameterDelegate().getResumptionOptions() != null;
        }
        throw new IllegalArgumentException(
                String.format("Invalid probe (%s) set for OptionsRequirement", type));
    }

    @Override
    public String toString() {
        if (domain != null) {
            return String.format("OptionsRequirement[%s with domain %s]", type, domain);
        } else {
            return String.format("OptionsRequirement[%s]", type);
        }
    }
}
