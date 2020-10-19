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

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.ICommandExecutor;
import de.rub.nds.tlsscanner.clientscanner.config.BaseSubcommand;
import de.rub.nds.tlsscanner.clientscanner.config.ISubcommand;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.IAdapterConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command.executors.IExecutorConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command.executors.LocalCommandExecutorConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command.executors.ProxiedLocalCommandExecutorConfig;

public abstract class BaseCommandAdapterConfig extends BaseSubcommand implements IAdapterConfig {
    public static Collection<ISubcommand> getAll() {
        return Arrays.asList(new CurlAdapterConfig());
    }

    public BaseCommandAdapterConfig() {
        subcommands.add(new LocalCommandExecutorConfig());
        subcommands.add(new ProxiedLocalCommandExecutorConfig());
    }

    @Override
    public void setParsed(JCommander jc) throws ParameterException {
        super.setParsed(jc);
        if (!(selectedSubcommand instanceof IExecutorConfig)) {
            throw new ParameterException("Selected subCommand does not implement IAdapterConfig");
        }
    }

    protected ICommandExecutor createCommandExecutor() {
        return ((IExecutorConfig) selectedSubcommand).createCommandExecutor();
    }

}
