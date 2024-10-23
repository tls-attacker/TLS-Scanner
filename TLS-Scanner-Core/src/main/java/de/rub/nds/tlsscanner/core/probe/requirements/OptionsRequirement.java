/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.ProbeType;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.config.TlsScannerConfig;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;

/** Represents a {@link Requirement} for additional, optional flags in commands. */
public abstract class OptionsRequirement<
                ReportT extends TlsScanReport, ConfigT extends TlsScannerConfig>
        extends Requirement<ReportT> {

    protected final ConfigT scannerConfig;

    /* ProbeType of the respective option. */
    protected final ProbeType probeType;

    /**
     * @param scannerConfig the {@link TlsScannerConfig}.
     * @param probeType the {@link ProbeType} of the option.
     */
    public OptionsRequirement(ConfigT scannerConfig, ProbeType probeType) {
        this.scannerConfig = scannerConfig;
        this.probeType = probeType;
    }
}
