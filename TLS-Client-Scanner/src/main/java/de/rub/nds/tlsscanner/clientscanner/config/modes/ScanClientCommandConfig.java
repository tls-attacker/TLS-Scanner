package de.rub.nds.tlsscanner.clientscanner.config.modes;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.Parameters;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.IClientAdapter;
import de.rub.nds.tlsscanner.clientscanner.config.BaseSubcommand;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.DockerLibAdapterConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.IAdapterConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.scan.command.BaseCommandAdapterConfig;

@Parameters(commandNames = "scanClient", commandDescription = "Scan a client automatically")
public class ScanClientCommandConfig extends BaseSubcommand {
    @Parameter(names = "-file", required = false, description = "File to write the report to as xml")
    private String reportFile = null;

    public ScanClientCommandConfig() {
        subcommands.add(new DockerLibAdapterConfig());
        subcommands.addAll(BaseCommandAdapterConfig.getAll());
    }

    @Override
    public void applyDelegate(Config config) {
        // use any port
        InboundConnection inboundConnection = config.getDefaultServerConnection();
        if (inboundConnection == null) {
            config.setDefaultServerConnection(new InboundConnection(0));
        } else {
            inboundConnection.setPort(0);
        }
    }

    public String getReportFile() {
        return reportFile;
    }

    @Override
    public void setParsed(JCommander jc) throws ParameterException {
        super.setParsed(jc);
        if (!(selectedSubcommand instanceof IAdapterConfig)) {
            throw new ParameterException("Selected subCommand does not implement IAdapterConfig");
        }
    }

    public IClientAdapter createClientAdapter() {
        return ((IAdapterConfig) selectedSubcommand).createClientAdapter();
    }

}
