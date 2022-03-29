/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.probe.result;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.scanner.core.report.PerformanceData;

public abstract class ProbeResult<T extends ScanReport> {

    private final ProbeType type;
    private long startTime;
    private long stopTime;

    public ProbeResult(ProbeType type) {
        this.type = type;
    }

    public ProbeType getType() {
        return type;
    }

    public String getProbeName() {
        return type.getName();
    }

    public PerformanceData getPerformanceData() {
        return new PerformanceData(type, startTime, stopTime);
    }

    public long getStartTime() {
        return startTime;
    }

    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }

    public long getStopTime() {
        return stopTime;
    }

    public void setStopTime(long stopTime) {
        this.stopTime = stopTime;
    }

    public void merge(T report) {
        if (startTime != 0 && stopTime != 0) {
            report.getPerformanceList().add(getPerformanceData());
        }
        this.mergeData(report);
        report.markAsChangedAndNotify();
    }

    protected abstract void mergeData(T report);
}
