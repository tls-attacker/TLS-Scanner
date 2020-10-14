package de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command;

import com.beust.jcommander.Parameters;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.IClientAdapter;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.CurlAdapter;

@Parameters(commandNames = "curl", commandDescription = "Use a curl based client")
public class CurlAdapterConfig extends BaseCommandAdapterConfig {
    @Override
    public void applyDelegate(Config config) {
        // nothing to do
    }

    @Override
    public IClientAdapter createClientAdapter() {
        return new CurlAdapter(createCommandExecutor());
    }

}
