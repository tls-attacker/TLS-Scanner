/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.data;

import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlscrawler.config.WorkerCommandConfig;
import de.rub.nds.tlscrawler.scans.IScan;
import de.rub.nds.tlscrawler.scans.NullScan;
import de.rub.nds.tlscrawler.scans.PingScan;
import de.rub.nds.tlscrawler.scans.TlsScan;
import java.io.Serializable;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ScanJob implements Serializable {

    private String scanName;

    private String workspace;

    private String scan;

    private int port;

    private int reexecutions;

    private int timeout;

    private StarttlsType starttlsType;

    private ScanJob() {
    }

    public ScanJob(String scanName, String workspace, String scan, int port, int reexecutions, int timeout, StarttlsType starttlsType) {
        this.scanName = scanName;
        this.workspace = workspace;
        this.scan = scan;
        this.reexecutions = reexecutions;
        this.timeout = timeout;
        this.port = port;
        this.starttlsType = starttlsType;
    }


    public IScan createIScanObject(WorkerCommandConfig config) {
        switch (getScan()) {
            case "tls":
                return new TlsScan(getTimeout(), config.getParallelProbeThreads(), getReexecutions(), starttlsType);
            case "ping":
                return new PingScan();
            case "null":
                return new NullScan();
            default:
                throw new UnsupportedOperationException("Scan " + getScan() + " not implemented");
        }
    }

}
