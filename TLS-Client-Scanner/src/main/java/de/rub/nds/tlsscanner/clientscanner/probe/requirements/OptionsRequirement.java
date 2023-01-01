/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;

public class OptionsRequirement extends Requirement {

    private ClientScannerConfig scannerConfig;
    private String type; // String name of the respective option
    private String domain; // domain for sni option (optional)

    /**
     * @param scannerConfig the ClientScannerConfig
     * @param type the name of the option
     */
    public OptionsRequirement(ClientScannerConfig scannerConfig, String type) {
        super();
        this.scannerConfig = scannerConfig;
        this.type = type;
    }

    /**
     * @param scannerConfig the ClientScannerConfig
     * @param type the name of the option
     * @param domain the domain for the sni option
     */
    public OptionsRequirement(ClientScannerConfig scannerConfig, String type, String domain) {
        super();
        this.scannerConfig = scannerConfig;
        this.type = type;
        this.domain = domain;
    }

    @Override
    protected boolean evaluateIntern(ScanReport report) {
        if (scannerConfig == null || type == null) {
            return false;
        }
        if (type == "ALPN") {
            return scannerConfig.getClientParameterDelegate().getAlpnOptions() != null;
        }

        // TODO is this correct for null domains?
        if (type == "SNI") {
            if (domain != null) {
                return scannerConfig.getClientParameterDelegate().getSniOptions(domain) != null;
            } else {
                return false;
            }
        }
        if (type == "RESUMPTION") {
            return scannerConfig.getClientParameterDelegate().getResumptionOptions() != null;
        }
        return false;
    }

    /**
     * @return the name of the option
     */
    public String getRequirement() {
        return type;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateIntern(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(new OptionsRequirement(scannerConfig, type)), report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
