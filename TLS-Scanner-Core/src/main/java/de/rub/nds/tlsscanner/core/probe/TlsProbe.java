/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe;

import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.scanner.core.report.PerformanceData;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class TlsProbe<ScanConfig extends ScannerConfig, Report extends ScanReport>
    extends ScannerProbe<Report> {

    protected static final Logger LOGGER = LogManager.getLogger();

    protected final ScanConfig scannerConfig;

    private final ParallelExecutor parallelExecutor;

    private Map<TlsAnalyzedProperty, TestResult> propertiesMap;

    protected TlsProbe(ParallelExecutor parallelExecutor, TlsProbeType type, ScanConfig scannerConfig) {
        super(type);
        this.scannerConfig = scannerConfig;
        this.parallelExecutor = parallelExecutor;
        this.propertiesMap = new HashMap<>();
    }

    public final ScanConfig getScannerConfig() {
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

    protected final void register(TlsAnalyzedProperty... properties) {
        if (properties.length > 0) {
            for (int i = 0; i < properties.length; i++)
                this.propertiesMap.put(properties[i], TestResults.UNASSIGNED_ERROR);
        }
    }

    protected final void put(TlsAnalyzedProperty aProp, TestResult result) {
        if (this.propertiesMap.containsKey(aProp))
            this.propertiesMap.replace(aProp, result);
        else { // unregistered property
            LOGGER.error(aProp.name() + " was set in " + this.getClass() + " but had not been registered!");
            this.propertiesMap.put(aProp, result);
        }
    }

    protected abstract void mergeData(Report report);

    public final void merge(Report report) {
        // merge data
        if (this.startTime != 0 && this.stopTime != 0)
            report.getPerformanceList().add(new PerformanceData(super.getType(), this.startTime, this.stopTime));
        this.mergeData(report);
        TestResult result;
        for (TlsAnalyzedProperty prop : this.propertiesMap.keySet()) {
            result = this.propertiesMap.get(prop);
            report.putResult(prop, result);
            if (result == TestResults.UNASSIGNED_ERROR)
                LOGGER.error(prop.name() + " in " + this.getClass() + " had not been assigned!");
        }
    }
}
