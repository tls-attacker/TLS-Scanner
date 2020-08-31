package de.rub.nds.tlsscanner.clientscanner.config;

import com.beust.jcommander.Parameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

public class ServerDelegate extends Delegate {

    @Parameter(names = "-port", required = true, description = "Port to listen on")
    protected Integer port = null;

    @Parameter(names = "-bindaddr", required = false, description = "Hostname/IP to listen on")
    protected String bindaddr = null;

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        config.setDefaultRunningMode(RunningModeType.SERVER);
        InboundConnection inboundConnection = config.getDefaultServerConnection();
        if (inboundConnection == null) {
            config.setDefaultServerConnection(new InboundConnection(port, bindaddr));
        } else {
            inboundConnection.setPort(port);
            inboundConnection.setHostname(bindaddr);
        }
    }

    public void setPort(int port) {
        this.port = port;
    }

}