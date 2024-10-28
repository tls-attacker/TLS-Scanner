/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.requirements;

import de.rub.nds.scanner.core.probe.ProbeType;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.OptionsRequirement;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

/** Represents a {@link Requirement} for additional, optional flags in commands. */
public class ServerOptionsRequirement
        extends OptionsRequirement<ServerReport, ServerScannerConfig> {

    public ServerOptionsRequirement(ServerScannerConfig scannerConfig, ProbeType probeType) {
        super(scannerConfig, probeType);
    }

    @Override
    public boolean evaluate(ServerReport report) {
        if (scannerConfig == null) {
            return false;
        }
        if (probeType instanceof TlsProbeType) {
            switch ((TlsProbeType) probeType) {
                case HTTP_HEADER:
                case HTTP_FALSE_START:
                    return scannerConfig.getApplicationProtocol() == ApplicationProtocol.HTTP
                            || scannerConfig.getApplicationProtocol()
                                    == ApplicationProtocol.UNKNOWN;
                case DTLS_IP_ADDRESS_IN_COOKIE:
                    return scannerConfig.getProxyDelegate().getExtractedControlProxyIp() != null
                            && scannerConfig.getProxyDelegate().getExtractedControlProxyPort() != -1
                            && scannerConfig.getProxyDelegate().getExtractedDataProxyIp() != null
                            && scannerConfig.getProxyDelegate().getExtractedDataProxyPort() != -1;
            }
        }
        throw new IllegalArgumentException(
                String.format("Invalid probe (%s) set for ServerOptionsRequirement", probeType));
    }

    @Override
    public String toString() {
        return String.format("ServerOptionsRequirement[%s]", probeType);
    }
}
