/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.requirements;

import static de.rub.nds.tlsscanner.core.constants.TlsProbeType.HTTP_FALSE_START;
import static de.rub.nds.tlsscanner.core.constants.TlsProbeType.HTTP_HEADER;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.OptionsRequirement;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

/** Represents a {@link Requirement} for additional, optional flags in commands. */
public class ServerOptionsRequirement
        extends OptionsRequirement<ServerReport, ServerScannerConfig> {

    public ServerOptionsRequirement(ServerScannerConfig scannerConfig, TlsProbeType probeType) {
        super(scannerConfig, probeType);
    }

    @Override
    public boolean evaluate(ServerReport report) {
        if (scannerConfig == null) {
            return false;
        }
        switch (probeType) {
            case HTTP_HEADER:
            case HTTP_FALSE_START:
                return scannerConfig.getApplicationProtocol() == ApplicationProtocol.HTTP
                        || scannerConfig.getApplicationProtocol() == ApplicationProtocol.UNKNOWN;
        }
        throw new IllegalArgumentException(
                String.format("Invalid probe (%s) set for ServerOptionsRequirement", probeType));
    }
}
