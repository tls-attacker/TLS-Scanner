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
import de.rub.nds.tlsscanner.core.probe.requirements.OptionsRequirement;

/** Represents a {@link Requirement} for additional, optional flags in commands. */
public class ClientOptionsRequirement
        extends OptionsRequirement<ClientReport, ClientScannerConfig> {

    public ClientOptionsRequirement(ClientScannerConfig scannerConfig, TlsProbeType probeType) {
        super(scannerConfig, probeType);
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
                return scannerConfig.getClientParameterDelegate().getSniOptions("") != null;
            case RESUMPTION:
                return scannerConfig.getClientParameterDelegate().getResumptionOptions() != null;
        }
        throw new IllegalArgumentException(
                String.format("Invalid probe (%s) set for ClientOptionsRequirement", probeType));
    }

    @Override
    public String toString() {
        return String.format("ClientOptionsRequirement[%s]", probeType);
    }
}
