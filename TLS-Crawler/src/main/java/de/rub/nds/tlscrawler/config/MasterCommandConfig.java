/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlscrawler.config.delegate.RedisDelegate;

/**
 *
 * @author robert
 */
public class MasterCommandConfig {

    @Parameter(names = "-portToBeScanned", description = "The port that should be scanned.")
    private int port = 443;

    @Parameter(names = "-timeout", description = "The timeout to use inside the TLS-Scanner.")
    private int scannerTimeout = 2000;

    @Parameter(names = "-reexecutions", description = "Number of reexecutions to use in the TLS-Scanner.")
    private int reexecutions = 3;

    @Parameter(names = "-scansToBeExecuted", description = "The number of scans that should be executed. 0 = indefinetly")
    private int scansToBeExecuted = 1;

    @Parameter(names = "-waitAfterScan", description = "The number of minutes to wait after a scan has completed. 0 = back to back")
    private int waitTimeAfterScan = 0;

    @Parameter(names = "-scanName", description = "The name of the scan")
    private String scanName;

    @Parameter(names = "-hostFile", description = "A file of a list of servers which should be scanned.")
    private String hostFile;

    @ParametersDelegate
    private RedisDelegate redisDelegate;

    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;

    public MasterCommandConfig() {
        redisDelegate = new RedisDelegate();
        starttlsDelegate = new StarttlsDelegate();
    }

    public StarttlsDelegate getStarttlsDelegate() {
        return starttlsDelegate;
    }
    
    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public int getScannerTimeout() {
        return scannerTimeout;
    }

    public void setScannerTimeout(int scannerTimeout) {
        this.scannerTimeout = scannerTimeout;
    }

    public int getReexecutions() {
        return reexecutions;
    }

    public void setReexecutions(int reexecutions) {
        this.reexecutions = reexecutions;
    }

    public int getScansToBeExecuted() {
        return scansToBeExecuted;
    }

    public void setScansToBeExecuted(int scansToBeExecuted) {
        this.scansToBeExecuted = scansToBeExecuted;
    }

    public int getWaitTimeAfterScan() {
        return waitTimeAfterScan;
    }

    public void setWaitTimeAfterScan(int waitTimeAfterScan) {
        this.waitTimeAfterScan = waitTimeAfterScan;
    }

    public String getScanName() {
        return scanName;
    }

    public void setScanName(String scanName) {
        this.scanName = scanName;
    }

    public String getHostFile() {
        return hostFile;
    }

    public void setHostFile(String hostFile) {
        this.hostFile = hostFile;
    }

    public RedisDelegate getRedisDelegate() {
        return redisDelegate;
    }
}
