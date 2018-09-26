/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
