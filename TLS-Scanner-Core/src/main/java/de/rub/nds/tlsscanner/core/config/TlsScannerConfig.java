/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsscanner.core.config.delegate.CallbackDelegate;
import de.rub.nds.tlsscanner.core.config.delegate.DtlsDelegate;

public class TlsScannerConfig extends ScannerConfig {

    @Parameter(
            names = "-timeout",
            required = false,
            description = "The timeout used for the scans in ms (default 1000)")
    private int timeout = 1000;

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

    @ParametersDelegate private DtlsDelegate dtlsDelegate;

    @ParametersDelegate private QuicDelegate quicDelegate;

    @ParametersDelegate private StarttlsDelegate startTlsDelegate;

    @ParametersDelegate private CallbackDelegate callbackDelegate;

    public TlsScannerConfig(GeneralDelegate delegate) {
        super(delegate);

        this.dtlsDelegate = new DtlsDelegate();
        this.quicDelegate = new QuicDelegate();
        this.startTlsDelegate = new StarttlsDelegate();
        this.callbackDelegate = new CallbackDelegate();

        addDelegate(dtlsDelegate);
        addDelegate(quicDelegate);
        addDelegate(startTlsDelegate);
        addDelegate(callbackDelegate);
    }

    public DtlsDelegate getDtlsDelegate() {
        return dtlsDelegate;
    }

    public QuicDelegate getQuicDelegate() {
        return quicDelegate;
    }

    public StarttlsDelegate getStartTlsDelegate() {
        return startTlsDelegate;
    }

    public CallbackDelegate getCallbackDelegate() {
        return callbackDelegate;
    }

    public int getTimeout() {
        return timeout;
    }

    public int getParallelProbes() {
        return parallelProbes;
    }

    public int getOverallThreads() {
        return overallThreads;
    }

    public boolean isMultithreaded() {
        return (parallelProbes > 1 || overallThreads > 1);
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public void setParallelProbes(int parallelProbes) {
        this.parallelProbes = parallelProbes;
    }

    public void setOverallThreads(int overallThreads) {
        this.overallThreads = overallThreads;
    }
}
