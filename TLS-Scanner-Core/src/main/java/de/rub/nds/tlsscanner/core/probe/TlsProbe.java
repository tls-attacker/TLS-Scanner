/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe;

import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class TlsProbe<Report extends ScanReport, Result extends ProbeResult<Report>>
    extends ScannerProbe<Report, Result> {

    protected static final Logger LOGGER = LogManager.getLogger();

    protected final ScannerConfig scannerConfig;

    private final ParallelExecutor parallelExecutor;

    protected TlsProbe(ParallelExecutor parallelExecutor, TlsProbeType type, ScannerConfig scannerConfig) {
        super(type);
        this.scannerConfig = scannerConfig;
        this.parallelExecutor = parallelExecutor;
    }

    public final ScannerConfig getScannerConfig() {
        return scannerConfig;
    }

    public final void executeState(State... states) {
        this.executeState(new ArrayList<>(Arrays.asList(states)));

    }

    public final void executeState(List<State> states) {

        parallelExecutor.bulkExecuteStateTasks(states);
        if (getWriter() != null) {
            for (State state : states) {
                getWriter().extract(state);
            }
        }

    }

    public ParallelExecutor getParallelExecutor() {
        return parallelExecutor;
    }
}
