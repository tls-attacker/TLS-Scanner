package de.rub.nds.tlsscanner.clientscanner.config;

import com.beust.jcommander.Parameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsscanner.clientscanner.util.IPUtil;

public class OrchestratorDelegate extends Delegate {
    @Parameter(names = "-serverBaseURL", required = false, description = "Base URL to use for the server. Defaults to 127.0.0.1.xip.io. Can be set to an IPv4, in this case -noSubdomain is implied")
    protected String serverBaseURL = "127.0.0.1.xip.io";
    @Parameter(names = "-noEntryDispatcher", description = "Do not add ChloEntryDispatcher, this allows probes to modify how the entry trace is created.")
    protected boolean noEntryDispatcher = false;
    @Parameter(names = "-singleDomain", description = "Use single domain instead of using unique subdomains for each probe. Note that this will most likely cause threading to be less effective")
    protected boolean singleDomain = false;

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        // Nothing to do
    }
    public String getServerBaseURL() {
        return serverBaseURL;
    }

    public boolean isServerBaseUrlAnIP() {
        return IPUtil.validIP(serverBaseURL);
    }

    public boolean isSingleDomain() {
        return isServerBaseUrlAnIP() || singleDomain;
    }

    public boolean isNoEntryDispatcher() {
        return noEntryDispatcher;
    }
}
