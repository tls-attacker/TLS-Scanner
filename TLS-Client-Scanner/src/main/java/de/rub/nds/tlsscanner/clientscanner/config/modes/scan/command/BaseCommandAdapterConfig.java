/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command;

import java.util.Arrays;
import java.util.Collection;

import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.CommandExecutor;
import de.rub.nds.tlsscanner.clientscanner.config.BaseSubcommandHolder;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.ClientAdapterConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command.executors.ExecutorConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command.executors.LocalCommandExecutorConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command.executors.ProxiedLocalCommandExecutorConfig;

public abstract class BaseCommandAdapterConfig extends BaseSubcommandHolder<ExecutorConfig>
        implements ClientAdapterConfig {
    public static Collection<ClientAdapterConfig> getAll() {
        return Arrays.asList(new CurlAdapterConfig());
    }

    public BaseCommandAdapterConfig() {
        subcommands.add(new LocalCommandExecutorConfig());
        subcommands.add(new ProxiedLocalCommandExecutorConfig());
    }

    protected CommandExecutor createCommandExecutor(ClientScannerConfig csConfig) {
        return selectedSubcommand.createCommandExecutor();
    }

}
