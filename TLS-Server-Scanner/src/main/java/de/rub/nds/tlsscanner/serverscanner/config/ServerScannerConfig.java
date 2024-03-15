/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsscanner.core.config.TlsScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.config.delegate.ProxyDelegate;
import de.rub.nds.tlsscanner.serverscanner.constants.ApplicationProtocol;
import java.util.List;

public class ServerScannerConfig extends TlsScannerConfig {

    @ParametersDelegate private ClientDelegate clientDelegate;

    @ParametersDelegate private CcaDelegate ccaDelegate;

    @ParametersDelegate private ProxyDelegate proxyDelegate;

    @Parameter(
            names = "-applicationProtocol",
            required = false,
            description = "Which application data protocol the server is running.")
    private ApplicationProtocol applicationProtocol = ApplicationProtocol.HTTP;

    @Parameter(
            names = "-additionalRandomCollection",
            required = false,
            description =
                    "Number of connections that should be additionally performed to collect more randomness data to get more accurate analysis")
    private int additionalRandomnessHandshakes = 0;

    @Parameter(
            names = "-ca",
            required = false,
            variableArity = true,
            description =
                    "Add one or more custom CA's by separating them with a comma to verify the corresponding chain of certificates.")
    private List<String> customCAPathList = null;

    @Parameter(names = "-vulns", required = false, description = "Vulnerabilities to look for")
    private String vulns = "";

    @Parameter(names = "-numexe", required = false, description = "Number of rexecutions")
    private int numexe = 3;

    @Parameter(
            names = "-configSearchCooldown",
            required = false,
            description =
                    "Pause between config tests to ensure the server finished processing the previously rejected messages")
    private boolean configSearchCooldown = false;

    public ServerScannerConfig(GeneralDelegate delegate) {
        super(delegate);

        this.clientDelegate = new ClientDelegate();
        this.ccaDelegate = new CcaDelegate();
        this.proxyDelegate = new ProxyDelegate();

        addDelegate(clientDelegate);
        addDelegate(ccaDelegate);
        addDelegate(proxyDelegate);
    }

    public ServerScannerConfig(GeneralDelegate delegate, ClientDelegate clientDelegate) {
        super(delegate);

        this.clientDelegate = clientDelegate;
        this.ccaDelegate = new CcaDelegate();
        this.proxyDelegate = new ProxyDelegate();

        addDelegate(clientDelegate);
        addDelegate(ccaDelegate);
        addDelegate(proxyDelegate);
    }

    public ApplicationProtocol getApplicationProtocol() {
        return applicationProtocol;
    }

    public void setApplicationProtocol(ApplicationProtocol applicationProtocol) {
        this.applicationProtocol = applicationProtocol;
    }

    public ClientDelegate getClientDelegate() {
        return clientDelegate;
    }

    public CcaDelegate getCcaDelegate() {
        return ccaDelegate;
    }

    public ProxyDelegate getProxyDelegate() {
        return proxyDelegate;
    }

    public int getAdditionalRandomnessHandshakes() {
        return additionalRandomnessHandshakes;
    }

    public void setAdditionalRandomnessHandshakes(int additionalRandomnessHandshakes) {
        this.additionalRandomnessHandshakes = additionalRandomnessHandshakes;
    }

    public List<String> getCustomCAPathList() {
        return customCAPathList;
    }

    public void setCustomCAPathList(List<String> customCAPathList) {
        this.customCAPathList = customCAPathList;
    }

    public boolean isConfigSearchCooldown() {
        return configSearchCooldown;
    }

    public void setConfigSearchCooldown(boolean configSearchCooldown) {
        this.configSearchCooldown = configSearchCooldown;
    }

    public int getNumexe() {
        return numexe;
    }

    public void setNumexe(int numexe) {
        this.numexe = numexe;
    }

    public String getVulns() {
        return vulns;
    }

    public void setVulns(String vulns) {
        this.vulns = vulns;
    }
}
