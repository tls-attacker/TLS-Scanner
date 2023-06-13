/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.constants.ScannerDetail;
import java.util.Arrays;
import java.util.List;

public final class ExecutorConfig {

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

    @Parameter(
            names = "-parallelProbes",
            required = false,
            description =
                    "Defines the number of threads responsible for different TLS probes. If set to 1, only one specific TLS probe (e.g., TLS version scan) can be run in time.")
    private int parallelProbes = 1;

    @Parameter(
            names = "-threads",
            required = false,
            description =
                    "The maximum number of threads used to execute TLS probes located in the scanning queue. This is also the maximum number of threads communicating with the analyzed peer.")
    private int overallThreads = 1;

    private List<ProbeType> probes = null;

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

    public int getParallelProbes() {
        return parallelProbes;
    }

    public void setParallelProbes(int parallelProbes) {
        this.parallelProbes = parallelProbes;
    }

    public int getOverallThreads() {
        return overallThreads;
    }

    public void setOverallThreads(int overallThreads) {
        this.overallThreads = overallThreads;
    }

    public boolean isMultithreaded() {
        return (parallelProbes > 1 || overallThreads > 1);
    }
}
