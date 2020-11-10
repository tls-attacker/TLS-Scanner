/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command.executors;

import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.CommandExecutor;

public interface IExecutorConfig {
    CommandExecutor createCommandExecutor();
}
