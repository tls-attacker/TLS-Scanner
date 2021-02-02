/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.config;

import java.util.List;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.ParametersDelegate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsscanner.clientscanner.config.modes.ScanClientCommandConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.StandaloneCommandConfig;

public class ClientScannerConfig extends TLSDelegateConfig {
    private static final Logger LOGGER = LogManager.getLogger();

    @ParametersDelegate
    protected CACertDelegate certificateDelegate;
    @ParametersDelegate
    protected StarttlsDelegate startTlsDelegate;
    @ParametersDelegate
    protected OrchestratorDelegate orchestratorDelegate;

    // #region Variables to be applied in Config
    @Parameter(names = "-timeout", required = false, description = "The timeout used for the scans in ms (default 1000)")
    protected int timeout = 1000;

    @Parameter(names = "-bindaddr", required = false, description = "Hostname/IP to listen on. Defaults to any")
    protected String bindaddr = null;
    // #endregion

    protected final JCommander jCommander;
    protected ExecutableSubcommand selectedSubcommand;

    public ClientScannerConfig() {
        this(new GeneralDelegate());
    }

    public ClientScannerConfig(GeneralDelegate delegate) {
        super(delegate);
        jCommander = new JCommander();
        jCommander.addObject(this);
        registerSubcommands();

        this.certificateDelegate = new CACertDelegate();
        addDelegate(certificateDelegate);

        this.startTlsDelegate = new StarttlsDelegate();
        addDelegate(startTlsDelegate);

        this.orchestratorDelegate = new OrchestratorDelegate();
        addDelegate(orchestratorDelegate);
    }

    protected void registerSubcommands() {
        new StandaloneCommandConfig().addToJCommander(jCommander);
        new ScanClientCommandConfig().addToJCommander(jCommander);
    }

    public void parse(String[] args) {
        jCommander.parse(args);
        if (getGeneralDelegate().isHelp()) {
            return;
        }
        String commandName = jCommander.getParsedCommand();
        if (commandName == null) {
            throw new ParameterException("No subcommand specified command (name is null)");
        }
        JCommander commandJc = jCommander.getCommands().get(commandName);
        List<Object> cmdObjs = commandJc.getObjects();
        ExecutableSubcommand cmd = (ExecutableSubcommand) cmdObjs.get(0);
        selectedSubcommand = cmd;
        selectedSubcommand.setParsed(commandJc);

        // final error handling
        if (selectedSubcommand == null) {
            throw new ParameterException("Could not parse command (is still null)");
        }
        // ensure generalDelegate is applied
        // it adds the BouncyCastle SecurityProvider
        getGeneralDelegate().applyDelegate(Config.createConfig());
    }

    public void usage() {
        jCommander.usage();
    }

    public void execute() {
        if (getGeneralDelegate().isHelp()) {
            usage();
            return;
        }
        selectedSubcommand.execute(this);
    }

    public void parseAndExecute(String[] args) {
        try {
            parse(args);
            execute();
        } catch (ParameterException E) {
            LOGGER.error("Could not parse provided parameters", E);
            usage();
        }
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig(Config.createConfig());
        config.getDefaultClientConnection().setTimeout(timeout);
        selectedSubcommand.applyDelegate(config);

        config.setDefaultRunningMode(RunningModeType.SERVER);
        InboundConnection inboundConnection = config.getDefaultServerConnection();
        if (inboundConnection == null) {
            config.setDefaultServerConnection(new InboundConnection(0, bindaddr));
        } else {
            inboundConnection.setHostname(bindaddr);
        }
        return config;
    }

    public ExecutableSubcommand getSelectedSubcommand() {
        return selectedSubcommand;
    }

    @SuppressWarnings({ "unchecked", "squid:S1172" })
    // unused parameter
    public <T> T getSelectedSubcommand(Class<T> expectedType) {
        return (T) selectedSubcommand;
    }

}
