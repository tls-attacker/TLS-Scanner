/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.report;

import de.rub.nds.scanner.core.constants.AnalyzedProperty;
import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.MapResult;
import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.constants.SetResult;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.passive.TrackableValue;
import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Observable;
import java.util.Set;

public abstract class ScanReport extends Observable implements Serializable {

    private final HashMap<String, TestResult> resultMap;

    private final Set<ProbeType> executedProbes;

    private final List<PerformanceData> performanceList;

    private Map<TrackableValue, ExtractedValueContainer> extractedValueContainerMap;

    private int performedTcpConnections = 0;

    public ScanReport() {
        performanceList = new LinkedList<>();
        resultMap = new HashMap<>();
        executedProbes = new HashSet<>();
        extractedValueContainerMap = new HashMap<>();
    }

    public synchronized int getPerformedTcpConnections() {
        return performedTcpConnections;
    }

    public synchronized void setPerformedTcpConnections(int performedTcpConnections) {
        this.performedTcpConnections = performedTcpConnections;
    }

    public synchronized Map<TrackableValue, ExtractedValueContainer> getExtractedValueContainerMap() {
        return extractedValueContainerMap;
    }

    public synchronized void
        setExtractedValueContainerList(Map<TrackableValue, ExtractedValueContainer> extractedValueContainerMap) {
        this.extractedValueContainerMap = extractedValueContainerMap;
    }

    public synchronized HashMap<String, TestResult> getResultMap() {
        return resultMap;
    }

    public synchronized TestResult getResult(AnalyzedProperty property) {
        return getResult(property.toString());
    }

    public synchronized TestResult getResult(String property) {
        TestResult result = resultMap.get(property);
        return (result == null) ? TestResults.NOT_TESTED_YET : result;
    }

    public synchronized ListResult<?> getListResult(AnalyzedProperty property) {
        return getListResult(property.getName());
    }

    public synchronized ListResult<?> getListResult(String property) {
        TestResult result = resultMap.get(property);
        return (result == null || !(result instanceof ListResult)) ? null : (ListResult<?>) result;
    }

    public synchronized MapResult<?, ?> getMapResult(AnalyzedProperty property) {
        return getMapResult(property.getName());
    }

    public synchronized MapResult<?, ?> getMapResult(String property) {
        TestResult result = resultMap.get(property);
        return (result == null || !(result instanceof MapResult)) ? null : (MapResult<?, ?>) result;
    }

    public synchronized SetResult<?> getSetResult(AnalyzedProperty property) {
        return getSetResult(property.getName());
    }

    public synchronized SetResult<?> getSetResult(String property) {
        TestResult result = resultMap.get(property);
        return (result == null || !(result instanceof SetResult)) ? null : (SetResult<?>) result;
    }

    public synchronized void removeResult(AnalyzedProperty property) {
        resultMap.remove(property.toString());
    }

    public synchronized void putResult(AnalyzedProperty property, TestResult result) {
        resultMap.put(property.toString(), result);
    }

    public synchronized void putResult(AnalyzedProperty property, Boolean result) {
        this.putResult(property, Objects.equals(result, Boolean.TRUE) ? TestResults.TRUE
            : Objects.equals(result, Boolean.FALSE) ? TestResults.FALSE : TestResults.UNCERTAIN);
    }

    public synchronized void markAsChangedAndNotify() {
        this.hasChanged();
        this.notifyObservers();
    }

    public synchronized boolean isProbeAlreadyExecuted(ProbeType type) {
        return (executedProbes.contains(type));
    }

    public synchronized void markProbeAsExecuted(ProbeType type) {
        executedProbes.add(type);
    }

    public synchronized List<PerformanceData> getPerformanceList() {
        return performanceList;
    }

    public synchronized Set<ProbeType> getExecutedProbes() {
        return executedProbes;
    }

    public abstract String getFullReport(ScannerDetail detail, boolean printColorful);
}
