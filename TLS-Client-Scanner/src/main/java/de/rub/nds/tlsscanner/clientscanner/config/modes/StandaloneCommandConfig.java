/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.config.modes;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsscanner.clientscanner.config.BaseSubcommand;

@Parameters(commandNames = "standalone", commandDescription = "Host probes publicly")
public class StandaloneCommandConfig extends BaseSubcommand {

    @Parameter(names = "-port", required = false, description = "Port to listen on")
    protected Integer port = 0;

    public StandaloneCommandConfig() {
        super();
        // TODO
    }

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        InboundConnection inboundConnection = config.getDefaultServerConnection();
        if (inboundConnection == null) {
            config.setDefaultServerConnection(new InboundConnection(port));
        } else {
            inboundConnection.setPort(port);
        }

    }

}
