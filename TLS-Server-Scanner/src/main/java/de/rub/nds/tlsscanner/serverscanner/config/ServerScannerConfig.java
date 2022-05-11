/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsscanner.serverscanner.config.delegate.CallbackDelegate;
import de.rub.nds.tlsscanner.serverscanner.config.delegate.DtlsDelegate;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import de.rub.nds.tlsscanner.serverscanner.trust.TrustAnchorManager;
import org.bouncycastle.util.IPAddress;
import java.util.List;

public class ServerScannerConfig extends ScannerConfig {

    @ParametersDelegate
    private ClientDelegate clientDelegate;

    @Parameter(names = "-parallelProbes", required = false,
        description = "Defines the number of threads responsible for different TLS probes. If set to 1, only one specific TLS probe (e.g., TLS version scan) can be run in time.")
    private int parallelProbes = 1;

    @Parameter(names = "-applicationProtocol", required = false,
        description = "Which application data protocol the server is running.")
    private ApplicationProtocol applicationProtocol = ApplicationProtocol.HTTP;

    @Parameter(names = "-threads", required = false,
        description = "The maximum number of threads used to execute TLS probes located in the scanning queue. This is also the maximum number of threads communicating with the analyzed server.")
    private int overallThreads = 1;

    @Parameter(names = "-timeout", required = false,
        description = "The timeout used for the scans in ms (default 1000)")
    private int timeout = 1000;

    @Parameter(names = "-additionalRandomCollection", required = false,
        description = "Number of connections that should be additionally performed to collect more randomness data to get more accurate analysis")
    private int additionalRandomnessHandshakes = 0;

    @Parameter(names = "-ca", required = false, variableArity = true,
        description = "Add one or more custom CA's by separating them with a comma to verify the corresponding chain of certificates.")
    private List<String> customCAPathList = null;

    @ParametersDelegate
    private CcaDelegate ccaDelegate;

    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;

    @ParametersDelegate
    private DtlsDelegate dtlsDelegate;

    @ParametersDelegate
    private CallbackDelegate callbackDelegate;

    private List<ProbeType> probes = null;

    private Config baseConfig = null;

    public ServerScannerConfig(GeneralDelegate delegate) {
        super(delegate);
        this.dtlsDelegate = new DtlsDelegate();
        this.clientDelegate = new ClientDelegate();
        this.starttlsDelegate = new StarttlsDelegate();
        this.ccaDelegate = new CcaDelegate();
        this.callbackDelegate = new CallbackDelegate();

        addDelegate(clientDelegate);
        addDelegate(starttlsDelegate);
        addDelegate(ccaDelegate);
        addDelegate(dtlsDelegate);
        addDelegate(callbackDelegate);
    }

    public ServerScannerConfig(GeneralDelegate delegate, ClientDelegate clientDelegate) {
        super(delegate);
        this.clientDelegate = clientDelegate;
        this.dtlsDelegate = new DtlsDelegate();
        this.starttlsDelegate = new StarttlsDelegate();
        this.ccaDelegate = new CcaDelegate();
        this.callbackDelegate = new CallbackDelegate();

        addDelegate(clientDelegate);
        addDelegate(starttlsDelegate);
        addDelegate(ccaDelegate);
        addDelegate(dtlsDelegate);
        addDelegate(callbackDelegate);
    }

    public ApplicationProtocol getApplicationProtocol() {
        return applicationProtocol;
    }

    public void setApplicationProtocol(ApplicationProtocol applicationProtocol) {
        this.applicationProtocol = applicationProtocol;
    }

    public int getOverallThreads() {
        return overallThreads;
    }

    public void setOverallThreads(int overallThreads) {
        this.overallThreads = overallThreads;
    }

    public int getParallelProbes() {
        return parallelProbes;
    }

    public void setParallelProbes(int parallelProbes) {
        this.parallelProbes = parallelProbes;
    }

    public ClientDelegate getClientDelegate() {
        return clientDelegate;
    }

    public StarttlsDelegate getStarttlsDelegate() {
        return starttlsDelegate;
    }

    public DtlsDelegate getDtlsDelegate() {
        return dtlsDelegate;
    }

    public CcaDelegate getCcaDelegate() {
        return ccaDelegate;
    }

    public CallbackDelegate getCallbackDelegate() {
        return callbackDelegate;
    }

    public int getAdditionalRandomnessHandshakes() {
        return additionalRandomnessHandshakes;
    }

    public void setAdditionalRandomnessHandshakes(int additionalRandomnessHandshakes) {
        this.additionalRandomnessHandshakes = additionalRandomnessHandshakes;
    }

    // TODO: remove or use in config selector
    @Override
    public Config createConfig() {
        if (baseConfig != null) {
            return baseConfig.createCopy();
        }

        Config config = super.createConfig(Config.createConfig());
        if (!IPAddress.isValid(config.getDefaultClientConnection().getHostname())
            || clientDelegate.getSniHostname() != null) {
            config.setAddServerNameIndicationExtension(true);
        } else {
            config.setAddServerNameIndicationExtension(false);
        }

        if (this.customCAPathList != null) {
            TrustAnchorManager.getInstance().addCustomCA(this.customCAPathList);
        }

        config.getDefaultClientConnection().setTimeout(timeout);
        if (timeout > AliasedConnection.DEFAULT_FIRST_TIMEOUT) {
            config.getDefaultClientConnection().setFirstTimeout(timeout);
        }
        return config;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public Config getBaseConfig() {
        return baseConfig;
    }

    public void setBaseConfig(Config baseConfig) {
        this.baseConfig = baseConfig;
    }

}
