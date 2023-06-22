/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe.requirements;

import static de.rub.nds.tlsscanner.core.constants.TlsProbeType.ALPN;
import static de.rub.nds.tlsscanner.core.constants.TlsProbeType.RESUMPTION;
import static de.rub.nds.tlsscanner.core.constants.TlsProbeType.SNI;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.OptionsRequirement;

/** Represents a {@link Requirement} for additional, optional flags in commands. */
public class ClientOptionsRequirement
        extends OptionsRequirement<ClientReport, ClientScannerConfig> {

    /* domain for sni option (optional). */
    private final String domain;

    public ClientOptionsRequirement(ClientScannerConfig scannerConfig, TlsProbeType probeType) {
        super(scannerConfig, probeType);
        this.domain = null;
    }

    public ClientOptionsRequirement(
            ClientScannerConfig scannerConfig, TlsProbeType probeType, String domain) {
        super(scannerConfig, probeType);
        this.domain = domain;
    }

    @Override
    public boolean evaluate(ClientReport report) {
        if (scannerConfig == null || probeType == null) {
            return false;
        }
        switch (probeType) {
            case ALPN:
                return scannerConfig.getClientParameterDelegate().getAlpnOptions() != null;
            case SNI:
                return domain != null
                        && scannerConfig.getClientParameterDelegate().getSniOptions(domain) != null;
            case RESUMPTION:
                return scannerConfig.getClientParameterDelegate().getResumptionOptions() != null;
        }
        throw new IllegalArgumentException(
                String.format("Invalid probe (%s) set for ClientOptionsRequirement", probeType));
    }

    @Override
    public String toString() {
        if (domain != null) {
            return String.format("ClientOptionsRequirement[%s with domain %s]", probeType, domain);
        } else {
            return String.format("ClientOptionsRequirement[%s]", probeType);
        }
    }
}
