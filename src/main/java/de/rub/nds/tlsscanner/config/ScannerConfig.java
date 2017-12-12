/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ScannerConfig extends TLSDelegateConfig {

    public static final String COMMAND = "scan";

    @ParametersDelegate
    private ClientDelegate clientDelegate;

    @Parameter(names = "-threads", required = false, description = "How many threads should execute Probes")
    private int threads = 1;

    @Parameter(names = "-danger", required = false, description = "Integer value (1 - 10) which specifies how aggressive the Scanner should test. Default 10")
    private int dangerLevel = 10;

    @ParametersDelegate
    private GeneralDelegate generalDelegate;

    @Parameter(names = "-implementation", required = false, description = "If you are interessted in the vulnerability of an implementation rather than a specific site")
    private boolean implementation = false;

    public ScannerConfig(GeneralDelegate delegate) {
        super(delegate);
        this.generalDelegate = delegate;
        clientDelegate = new ClientDelegate();
        addDelegate(clientDelegate);
        addDelegate(generalDelegate);
    }

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

    public ClientDelegate getClientDelegate() {
        return clientDelegate;
    }

    public int getDangerLevel() {
        return dangerLevel;
    }

    public void setDangerLevel(int dangerLevel) {
        this.dangerLevel = dangerLevel;
    }

    public boolean isImplementation() {
        return implementation;
    }

    public void setImplementation(boolean implementation) {
        this.implementation = implementation;
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        config.setSniHostname(clientDelegate.getHost());
        config.getDefaultClientConnection().setTimeout(1000);
        return config;
    }
    
    
}
