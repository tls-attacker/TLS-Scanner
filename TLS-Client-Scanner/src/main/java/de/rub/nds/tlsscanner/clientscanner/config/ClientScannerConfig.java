/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;

public class ClientScannerConfig extends ScannerConfig {

    @ParametersDelegate
    protected ServerDelegate serverDelegate;

    @ParametersDelegate
    protected StarttlsDelegate startTlsDelegate;

    @Parameter(names = "-timeout", required = false,
        description = "The timeout used for the scans in ms (default 1000)")
    protected int timeout = 1000;

    @Parameter(names = "-run", required = false,
        description = "The shell command the scanner should run to start the client. The port number the client should connect to should be marked with [port]")
    protected String runCommand = null;

    @Parameter(names = "-parallelProbes", required = false,
        description = "Defines the number of threads responsible for different TLS probes. If set to 1, only one specific TLS probe (e.g., TLS version scan) can be run in time.")
    private int parallelProbes = 1;

    @Parameter(names = "-threads", required = false,
        description = "The maximum number of threads used to execute TLS probes located in the scanning queue. This is also the maximum number of threads communicating with the analyzed server.")
    private int overallThreads = 1;

    public ClientScannerConfig() {
        this(new GeneralDelegate());
    }

    public ClientScannerConfig(GeneralDelegate delegate) {
        super(delegate);
        this.startTlsDelegate = new StarttlsDelegate();
        addDelegate(startTlsDelegate);
        this.serverDelegate = new ServerDelegate();
        addDelegate(serverDelegate);

    }

    @Override
    public Config createConfig() {
        if (getGeneralDelegate().isDebug()) {
            Configurator.setAllLevels("de.rub.nds.tlsscanner", Level.DEBUG);
        } else if (getGeneralDelegate().isQuiet()) {
            Configurator.setAllLevels("de.rub.nds.tlsscanner", Level.OFF);
        }

        Config config = super.createConfig(Config.createConfig());
        config.getDefaultClientConnection().setTimeout(timeout);
        return config;
    }

    public int getTimeout() {
        return timeout;
    }

    public String getRunCommand() {
        return runCommand;
    }

    public int getParallelProbes() {
        return parallelProbes;
    }

    public int getOverallThreads() {
        return overallThreads;
    }

    public ServerDelegate getServerDelegate() {
        return serverDelegate;
    }
}
