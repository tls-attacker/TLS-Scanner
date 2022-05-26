/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class TlsClientProbe<ClientScannerConfig, Report extends ScanReport> extends TlsProbe<Report> {

    protected static final Logger LOGGER = LogManager.getLogger();

    protected final ClientScannerConfig scannerConfig;

    protected TlsClientProbe(ParallelExecutor parallelExecutor, TlsProbeType type, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, type);
        this.scannerConfig = scannerConfig;
    }
}