/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.config.modes.scan;

import java.util.List;
import java.util.function.UnaryOperator;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.Parameters;
import com.github.dockerjava.api.model.HostConfig;

import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.ClientAdapter;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.DockerLibAdapter;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;

@Parameters(commandNames = "docker", commandDescription = "Use a docker client (based on TLS-Docker-Library)")
public class DockerLibAdapterConfig implements ClientAdapterConfig {
    @Parameter(names = "-type", required = true, description = "Type to use")
    protected TlsImplementationType type = null;
    @Parameter(names = "-version", required = true, description = "Version of client to use")
    protected String version = null;
    @Parameter(names = "-DNS", required = false, description = "DNS Server entry to add to the docker container(s). Useful if containers experience DNS problems")
    protected List<String> dns = null;

    @Override
    public void applyDelegate(Config config) {
        // nothing to do
    }

    @Override
    public void setParsed(JCommander jc) throws ParameterException {
        // nothing to do
    }

    @Override
    public ClientAdapter createClientAdapter(ClientScannerConfig csConfig) {
        UnaryOperator<HostConfig> hostConfigHook = null;
        if (dns != null) {
            hostConfigHook = cfg -> cfg.withDns(dns);
        }
        return new DockerLibAdapter(type, version, hostConfigHook);
    }
}
