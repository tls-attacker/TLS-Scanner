/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;

/**
 *
 * @author robert
 */
public class PerformanceData {

    private ProbeType type;
    private long starttime;
    private long stoptime;

    private PerformanceData() {
    }

    public PerformanceData(ProbeType type, long starttime, long stoptime) {
        this.type = type;
        this.starttime = starttime;
        this.stoptime = stoptime;
    }

    public ProbeType getType() {
        return type;
    }

    public void setType(ProbeType type) {
        this.type = type;
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

}
