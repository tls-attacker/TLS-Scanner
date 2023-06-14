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
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

/**
 * Represents a {@link Requirement} for additional, optional flags in commands. Can be extended by
 * adding a respective if clause in the evaluateIntern function.
 */
public class OptionsRequirement extends Requirement {

    private ClientScannerConfig scannerConfig;

    /* Probetype of the respective option. */
    private TlsProbeType type;

    /* domain for sni option (optional). */
    private String domain;

    /**
     * @param scannerConfig the {@link ClientScannerConfig}.
     * @param type the {@link TlsProbeType} of the option.
     */
    public OptionsRequirement(ClientScannerConfig scannerConfig, TlsProbeType type) {
        super();
        this.scannerConfig = scannerConfig;
        this.type = type;
    }

    /**
     * @param scannerConfig the {@link ClientScannerConfig}.
     * @param type the {@link TlsProbeType} of the option.
     * @param domain the domain for the sni option.
     */
    public OptionsRequirement(ClientScannerConfig scannerConfig, TlsProbeType type, String domain) {
        super();
        this.scannerConfig = scannerConfig;
        this.type = type;
        this.domain = domain;
    }

    @Override
    protected boolean evaluateInternal(ScanReport report) {
        if (scannerConfig == null || type == null) {
            return false;
        }
        if (type == TlsProbeType.ALPN) {
            return scannerConfig.getClientParameterDelegate().getAlpnOptions() != null;
        }
        if (type == TlsProbeType.SNI) {
            if (domain != null) {
                return scannerConfig.getClientParameterDelegate().getSniOptions(domain) != null;
            } else {
                return false;
            }
        }
        if (type == TlsProbeType.RESUMPTION) {
            return scannerConfig.getClientParameterDelegate().getResumptionOptions() != null;
        }
        return false;
    }

    @Override
    public String toString() {
        if (domain == null) {
            return "Option of " + type.toString() + "with domain " + domain;
        }
        return "Option of " + type.toString();
    }

    @Override
    public Enum<?>[] getRequirement() {
        if (type == null) {
            return new Enum<?>[] {null};
        } else {
            switch (type) {
                case ALPN:
                    return new Enum<?>[] {SpecialRequirementTypes.OPTIONS_ALPN};
                case SNI:
                    return new Enum<?>[] {SpecialRequirementTypes.OPTIONS_SNI};
                case RESUMPTION:
                    return new Enum<?>[] {SpecialRequirementTypes.OPTIONS_RESUMPTION};
                default:
                    throw new IllegalArgumentException(
                            "Invalid probe (" + type.name() + ") set for OptionsRequirement");
            }
        }
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateInternal(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(new OptionsRequirement(scannerConfig, type)), report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
