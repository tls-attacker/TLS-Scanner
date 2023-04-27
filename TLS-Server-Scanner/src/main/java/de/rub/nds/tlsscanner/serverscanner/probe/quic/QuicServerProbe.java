/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.quic;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.probe.QuicProbe;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class QuicServerProbe<
                ConfigSelector, Report extends TlsScanReport, Result extends ProbeResult<Report>>
        extends QuicProbe<Report, Result> {

    protected static final Logger LOGGER = LogManager.getLogger();

    protected final ConfigSelector configSelector;

    protected QuicServerProbe(
            ParallelExecutor parallelExecutor, ProbeType type, ConfigSelector configSelector) {
        super(parallelExecutor, type);
        this.configSelector = configSelector;
    }
}
