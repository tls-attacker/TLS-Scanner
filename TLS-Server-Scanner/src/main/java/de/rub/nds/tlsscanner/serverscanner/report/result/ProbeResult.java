/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.PerformanceData;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public abstract class ProbeResult {

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
        return type.name();
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

    public void merge(SiteReport report) {
        report.getPerformanceList().add(getPerformanceData());
        this.mergeData(report);
        report.markAsChangedAndNotify();
    }

    protected abstract void mergeData(SiteReport report);
}
