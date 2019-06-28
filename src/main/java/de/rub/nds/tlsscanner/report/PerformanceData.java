/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report;

import de.rub.nds.tlsscanner.constants.ProbeType;

/**
 *
 * @author robert
 */
public class PerformanceData {

    private ProbeType type;
    private long starttime;
    private long stoptime;

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
