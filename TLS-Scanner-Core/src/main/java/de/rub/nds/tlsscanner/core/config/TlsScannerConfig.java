/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.scanner.core.config.ExecutorConfig;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsscanner.core.config.delegate.CallbackDelegate;
import de.rub.nds.tlsscanner.core.config.delegate.DtlsDelegate;

public class TlsScannerConfig extends TLSDelegateConfig {

    @Parameter(
            names = "-timeout",
            required = false,
            description = "The timeout used for the scans in ms (default 1000)")
    private int timeout = 1000;

    @ParametersDelegate private DtlsDelegate dtlsDelegate;

    @ParametersDelegate private QuicDelegate quicDelegate;

    @ParametersDelegate private StarttlsDelegate startTlsDelegate;

    @ParametersDelegate private CallbackDelegate callbackDelegate;

    @ParametersDelegate private ExecutorConfig executorConfig;

    public TlsScannerConfig(GeneralDelegate delegate) {
        super(delegate);

        this.dtlsDelegate = new DtlsDelegate();
        this.quicDelegate = new QuicDelegate();
        this.startTlsDelegate = new StarttlsDelegate();
        this.callbackDelegate = new CallbackDelegate();
        this.executorConfig = new ExecutorConfig();

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

    public ExecutorConfig getExecutorConfig() {
        return executorConfig;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }
}
