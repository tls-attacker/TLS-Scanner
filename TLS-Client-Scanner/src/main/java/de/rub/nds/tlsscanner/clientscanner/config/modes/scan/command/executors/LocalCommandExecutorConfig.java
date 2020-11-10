/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command.executors;

import com.beust.jcommander.Parameters;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.CommandExecutor;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.LocalCommandExecutor;
import de.rub.nds.tlsscanner.clientscanner.config.BaseSubcommand;

@Parameters(commandNames = "local", commandDescription = "Use local command executor which executes the commands on your local system")
public class LocalCommandExecutorConfig extends BaseSubcommand implements IExecutorConfig {
    @Override
    public void applyDelegate(Config config) {
        // nothing to do
    }

    @Override
    public CommandExecutor createCommandExecutor() {
        return new LocalCommandExecutor();
    }

}
