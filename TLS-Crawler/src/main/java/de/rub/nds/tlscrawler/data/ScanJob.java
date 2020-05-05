/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.data;

import de.rub.nds.tlscrawler.config.SlaveCommandConfig;
import de.rub.nds.tlscrawler.scans.IScan;
import de.rub.nds.tlscrawler.scans.NullScan;
import de.rub.nds.tlscrawler.scans.PingScan;
import de.rub.nds.tlscrawler.scans.TlsScan;
import java.io.Serializable;

public class ScanJob implements Serializable {

    private String scanName;

    private String workspace;

    private String scan;

    private int port;

    private int reexecutions;

    private int timeout;

    public ScanJob(String scanName, String workspace, String scan, int port, int reexecutions, int timeout) {
        this.scanName = scanName;
        this.workspace = workspace;
        this.scan = scan;
        this.reexecutions = reexecutions;
        this.timeout = timeout;
        this.port = port;
    }

    public String getScanName() {
        return scanName;
    }

    public void setScanName(String scanName) {
        this.scanName = scanName;
    }

    public String getWorkspace() {
        return workspace;
    }

    public void setWorkspace(String workspace) {
        this.workspace = workspace;
    }

    public String getScan() {
        return scan;
    }

    public void setScan(String scan) {
        this.scan = scan;
    }

    public IScan createIScanObject(SlaveCommandConfig config) {
        switch (getScan()) {
            case "tls":
                return new TlsScan(getTimeout(), config.getParallelProbeThreads(), getReexecutions());
            case "ping":
                return new PingScan();
            case "null":
                return new NullScan();
            default:
                throw new UnsupportedOperationException("Scan " + getScan() + " not implemented");
        }
    }

    public int getReexecutions() {
        return reexecutions;
    }

    public void setReexecutions(int reexecutions) {
        this.reexecutions = reexecutions;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }
}
