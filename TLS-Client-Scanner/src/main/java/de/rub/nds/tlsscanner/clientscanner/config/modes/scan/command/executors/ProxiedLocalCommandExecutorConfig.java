/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command.executors;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.CommandExecutor;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.ProxiedLocalCommandExecutor;
import de.rub.nds.tlsscanner.clientscanner.config.BaseSubcommand;

@Parameters(commandNames = "localProxied", commandDescription = "Use local command executor which passes the command as an argument to another command (e.g. bash)")
public class ProxiedLocalCommandExecutorConfig extends BaseSubcommand implements IExecutorConfig {
    @Parameter(names = "-proxy", required = true, description = "Proxy command to use. Example \"bash -c\"")
    protected String proxy = null;

    @Override
    public void applyDelegate(Config config) {
        // nothing to do
    }

    @Override
    public CommandExecutor createCommandExecutor() {
        return new ProxiedLocalCommandExecutor(proxy.split(" "));
    }
}
