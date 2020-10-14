package de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command.executors;

import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.ICommandExecutor;

public interface IExecutorConfig {
    ICommandExecutor createCommandExecutor();
}
