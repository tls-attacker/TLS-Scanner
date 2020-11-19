/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.PerformanceData;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class ProbeResult {

    private final ProbeType type;
    private long starttime;
    private long stoptime;

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
        return new PerformanceData(type, starttime, stoptime);
    }

    public long getStarttime() {
        return starttime;
    }

    public void setStarttime(long starttime) {
        this.starttime = starttime;
    }

    public long getStoptime() {
        return stoptime;
    }

    public void setStoptime(long stoptime) {
        this.stoptime = stoptime;
    }

    public void merge(SiteReport report) {
        report.getPerformanceList().add(getPerformanceData());
        this.mergeData(report);
        report.markAsChangedAndNotify();
    }

    protected abstract void mergeData(SiteReport report);
}
