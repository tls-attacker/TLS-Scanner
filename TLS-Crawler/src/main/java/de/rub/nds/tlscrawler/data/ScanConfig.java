/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.data;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlscrawler.scans.ScanType;
import java.io.Serializable;

public class ScanConfig implements Serializable {

    private ScanType scanType;

    private int defaultPort;

    private ScannerDetail scannerDetail;

    private int reexecutions;

    private int timeout;

    private StarttlsType starttlsType;

    private ScanConfig() {}

    public ScanConfig(
            ScanType scanType,
            int defaultPort,
            ScannerDetail scannerDetail,
            int reexecutions,
            int timeout,
            StarttlsType starttlsType) {
        this.scanType = scanType;
        this.defaultPort = defaultPort;
        this.scannerDetail = scannerDetail;
        this.reexecutions = reexecutions;
        this.timeout = timeout;
        this.starttlsType = starttlsType;
    }

    public ScanType getScanType() {
        return this.scanType;
    }

    public int getDefaultPort() {
        return this.defaultPort;
    }

    public ScannerDetail getScannerDetail() {
        return this.scannerDetail;
    }

    public int getReexecutions() {
        return this.reexecutions;
    }

    public int getTimeout() {
        return this.timeout;
    }

    public StarttlsType getStarttlsType() {
        return this.starttlsType;
    }

    public void setScanType(ScanType scanType) {
        this.scanType = scanType;
    }

    public void setDefaultPort(int defaultPort) {
        this.defaultPort = defaultPort;
    }

    public void setScannerDetail(ScannerDetail scannerDetail) {
        this.scannerDetail = scannerDetail;
    }

    public void setReexecutions(int reexecutions) {
        this.reexecutions = reexecutions;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public void setStarttlsType(StarttlsType starttlsType) {
        this.starttlsType = starttlsType;
    }
}
