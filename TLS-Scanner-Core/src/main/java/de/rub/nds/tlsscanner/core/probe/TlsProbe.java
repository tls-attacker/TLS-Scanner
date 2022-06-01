/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.MapResult;
import de.rub.nds.scanner.core.constants.SetResult;
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
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class TlsProbe<Report extends ScanReport> extends ScannerProbe<Report> {

    protected static final Logger LOGGER = LogManager.getLogger();

    private final ParallelExecutor parallelExecutor;

    private Map<TlsAnalyzedProperty, TestResult> propertiesMap;

    protected TlsProbe(ParallelExecutor parallelExecutor, TlsProbeType type) {
        super(type);
        this.parallelExecutor = parallelExecutor;
        this.propertiesMap = new HashMap<>();
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
        for (int i = 0; i < properties.length; i++)
            propertiesMap.put(properties[i], TestResults.UNASSIGNED_ERROR);
    }

    protected final void put(TlsAnalyzedProperty aProp, Object value) {
        if (aProp == null) {
            LOGGER.error("Property to put (put) in " + getClass() + " is null!");
            return;
        }
        TestResult result = null;
        if (value != null) {
            if (value instanceof TestResult)
                result = (TestResult) value;
            else if (value instanceof List<?>)
                result = new ListResult<>((List<?>) value, aProp.name());
            else if (value instanceof Map<?, ?>)
                result = new MapResult<>((Map<?, ?>) value, aProp.name());
            else if (value instanceof Set<?>)
                result = new SetResult<>((Set<?>) value, aProp.name());
            else // something went wrong and the put method received neither any TestResult object nor a set, list or
                 // map as
                 // expected!!
                result = TestResults.ERROR_DURING_TEST;
        }
        if (propertiesMap.containsKey(aProp))
            propertiesMap.replace(aProp, result);
        else { // unregistered property
            LOGGER.error(aProp.name() + " was set in " + getClass() + " but had not been registered!");
            propertiesMap.put(aProp, result);
        }
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    protected final void addToList(TlsAnalyzedProperty aProp, List<?> result) {
        if (aProp == null) {
            LOGGER.error("Property to add (addToList) to in " + getClass() + " is null!");
            return;
        }
        if (propertiesMap.containsKey(aProp)) {
            if (result != null) {
                if (propertiesMap.get(aProp).getClass().equals(ListResult.class)) {
                    result.addAll(((ListResult) propertiesMap.get(aProp)).getList());
                    put(aProp, new ListResult<>(result, aProp.name()));
                } else
                    put(aProp, new ListResult<>(result, aProp.name()));
            }
        } else { // unregistered property
            LOGGER.error(aProp.name() + " was set in " + getClass() + " but had not been registered!");
            propertiesMap.put(aProp, new ListResult<>(result, aProp.name()));
        }
    }

    protected abstract void mergeData(Report report);

    public final void merge(Report report) {
        // merge data
        if (startTime != 0 && stopTime != 0)
            report.getPerformanceList().add(new PerformanceData(super.getType(), startTime, stopTime));
        mergeData(report);
        TestResult result;
        for (TlsAnalyzedProperty prop : propertiesMap.keySet()) {
            result = propertiesMap.get(prop);
            report.putResult(prop, result);
            if (result == TestResults.UNASSIGNED_ERROR)
                LOGGER.error(prop.name() + " in " + getClass() + " had not been assigned!");
        }
    }
}
