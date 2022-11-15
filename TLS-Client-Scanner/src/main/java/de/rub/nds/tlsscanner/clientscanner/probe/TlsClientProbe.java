/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

<<<<<<< HEAD
import de.rub.nds.scanner.core.report.ScanReport;
=======
import de.rub.nds.scanner.core.probe.result.ProbeResult;
>>>>>>> master
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

<<<<<<< HEAD
public abstract class TlsClientProbe<ClientScannerConfig, Report extends ScanReport> extends TlsProbe<Report> {
=======
public abstract class TlsClientProbe<
                ClientScannerConfig,
                Report extends TlsScanReport,
                Result extends ProbeResult<Report>>
        extends TlsProbe<Report, Result> {
>>>>>>> master

    protected static final Logger LOGGER = LogManager.getLogger();

    protected final ClientScannerConfig scannerConfig;

    protected TlsClientProbe(
            ParallelExecutor parallelExecutor,
            TlsProbeType type,
            ClientScannerConfig scannerConfig) {
        super(parallelExecutor, type);
        this.scannerConfig = scannerConfig;
    }
}
