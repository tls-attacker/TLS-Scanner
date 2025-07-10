/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe;

import de.rub.nds.scanner.core.probe.ProbeType;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class TlsProbe<ReportT extends TlsScanReport> extends ScannerProbe<ReportT, State> {

    protected static final Logger LOGGER = LogManager.getLogger();

    private final ParallelExecutor parallelExecutor;

    protected TlsProbe(ParallelExecutor parallelExecutor, ProbeType type) {
        super(type);
        this.parallelExecutor = parallelExecutor;
    }

    public final void executeState(State... states) {
        this.executeState(Arrays.asList(states));
    }

    public final void executeState(Iterable<State> states) {
        try {
            parallelExecutor.bulkExecuteStateTasks(states);
            extractStats(states);
        } catch (de.rub.nds.tlsattacker.core.exceptions.TransportHandlerConnectException e) {
            LOGGER.warn("Connection failed during probe execution: {}", e.getMessage());
            // Don't propagate the exception, allowing the scan to continue with other probes
        } catch (RuntimeException e) {
            if (e.getMessage() != null
                    && e.getMessage().contains("Cannot add Tasks to already shutdown executor")) {
                LOGGER.warn(
                        "ParallelExecutor was shutdown during execution, skipping remaining tasks");
            } else {
                LOGGER.error("Exception during probe execution: {}", e.getMessage(), e);
            }
            // Log the exception but don't crash the scanner
        } catch (Exception e) {
            LOGGER.error("Exception during probe execution: {}", e.getMessage(), e);
            // Log the full exception but don't crash the scanner
        }
    }

    @Override
    public ProbeType getType() {
        return super.getType();
    }

    public ParallelExecutor getParallelExecutor() {
        return parallelExecutor;
    }
}
