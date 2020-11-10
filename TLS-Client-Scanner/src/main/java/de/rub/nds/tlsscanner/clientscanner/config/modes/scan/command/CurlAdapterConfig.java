/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command;

import com.beust.jcommander.Parameters;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.ClientAdapter;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.CurlAdapter;

@Parameters(commandNames = "curl", commandDescription = "Use a curl based client")
public class CurlAdapterConfig extends BaseCommandAdapterConfig {
    @Override
    public void applyDelegate(Config config) {
        // nothing to do
    }

    @Override
    public ClientAdapter createClientAdapter() {
        return new CurlAdapter(createCommandExecutor());
    }

}
