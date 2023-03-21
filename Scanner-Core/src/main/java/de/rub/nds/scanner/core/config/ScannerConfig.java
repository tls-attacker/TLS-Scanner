/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public abstract class ScannerConfig extends TLSDelegateConfig {

    @Parameter(
            names = "-noColor",
            required = false,
            description = "If you use Windows or don't want colored text.")
    private boolean noColor = false;

    @Parameter(
            names = "-scanDetail",
            required = false,
            description = "How detailed do you want to scan?")
    private ScannerDetail scanDetail = ScannerDetail.NORMAL;

    @Parameter(
            names = "-reportDetail",
            required = false,
            description = "How detailed do you want the report to be?")
    private ScannerDetail reportDetail = ScannerDetail.NORMAL;

    @Parameter(
            names = "-outputFile",
            required = false,
            description = "Specify a file to write the site report in JSON to")
    private String outputFile = null;

    @Parameter(
            names = "-probeTimeout",
            required = false,
            description = "The timeout for each probe in ms (default 1800000)")
    private int probeTimeout = 1800000;

    protected List<ProbeType> probes = null;

    public ScannerConfig(GeneralDelegate delegate) {
        super(delegate);
    }

    public ScannerDetail getScanDetail() {
        return scanDetail;
    }

    public void setScanDetail(ScannerDetail scanDetail) {
        this.scanDetail = scanDetail;
    }

    public ScannerDetail getReportDetail() {
        return reportDetail;
    }

    public void setReportDetail(ScannerDetail reportDetail) {
        this.reportDetail = reportDetail;
    }

    public boolean isNoColor() {
        return noColor;
    }

    public void setNoColor(boolean noColor) {
        this.noColor = noColor;
    }

    public List<ProbeType> getProbes() {
        return probes;
    }

    public void setProbes(List<ProbeType> probes) {
        this.probes = probes;
    }

    public void setProbes(ProbeType... probes) {
        this.probes = Arrays.asList(probes);
    }

    public void addProbes(List<ProbeType> probes) {
        if (this.probes == null) {
            this.probes = new LinkedList<>();
        }
        this.probes.addAll(probes);
    }

    public void addProbes(ProbeType... probes) {
        if (this.probes == null) {
            this.probes = new LinkedList<>();
        }
        this.probes.addAll(Arrays.asList(probes));
    }

    public int getProbeTimeout() {
        return probeTimeout;
    }

    public void setProbeTimeout(int probeTimeout) {
        this.probeTimeout = probeTimeout;
    }

    public boolean isWriteReportToFile() {
        return outputFile != null;
    }

    public String getOutputFile() {
        return outputFile;
    }

    public void setOutputFile(String outputFile) {
        this.outputFile = outputFile;
    }
}
