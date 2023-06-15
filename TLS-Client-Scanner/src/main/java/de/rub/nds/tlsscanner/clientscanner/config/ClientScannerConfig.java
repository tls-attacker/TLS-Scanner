/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ServerUdpTransportHandler;
import de.rub.nds.tlsscanner.clientscanner.config.delegate.ClientParameterDelegate;
import de.rub.nds.tlsscanner.core.config.TlsScannerConfig;
import java.io.File;
import java.io.IOException;
import java.util.function.Function;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;

public class ClientScannerConfig extends TlsScannerConfig {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String PORT_REPLACEMENT_MARKER = "[port]";
    private static final String CLIENT_RUN_LOG_SUFFIX = "_client.log";

    @ParametersDelegate private ServerDelegate serverDelegate;

    @ParametersDelegate private ClientParameterDelegate clientParameterDelegate;

    @Parameter(
            names = "-run",
            required = true,
            description =
                    "The shell command the scanner should run to start the client. The port number the client should connect to must be marked with '"
                            + PORT_REPLACEMENT_MARKER
                            + "'")
    private String runCommand = null;

    @Parameter(
            names = "-runDirectory",
            required = false,
            description = "The working directory the scanner should use when starting the client")
    private String runDirectory = null;

    @Parameter(
            names = "-logDirectory",
            required = false,
            description =
                    "The directory the scanner should use to log the client output. Be wary: This creates a lot of files for a full scan")
    private String logDirectory = null;
    
    private Function<State, Integer> externalRunCallback = null;

    public ClientScannerConfig(GeneralDelegate delegate) {
        super(delegate);

        this.serverDelegate = new ServerDelegate();
        this.clientParameterDelegate = new ClientParameterDelegate();

        addDelegate(serverDelegate);
        addDelegate(clientParameterDelegate);
    }

    @Override
    public Config createConfig() {
        if (getGeneralDelegate().isDebug()) {
            Configurator.setAllLevels("de.rub.nds.tlsscanner", Level.DEBUG);
        } else if (getGeneralDelegate().isQuiet()) {
            Configurator.setAllLevels("de.rub.nds.tlsscanner", Level.OFF);
        }

        Config config = super.createConfig(Config.createConfig());
        config.getDefaultClientConnection().setTimeout(getTimeout());
        config.setRespectClientProposedExtensions(true);
        // will only be added if proposed by client
        config.setAddRenegotiationInfoExtension(true);
        return config;
    }

    public String getRunCommand() {
        return runCommand;
    }

    public ServerDelegate getServerDelegate() {
        return serverDelegate;
    }

    public ClientParameterDelegate getClientParameterDelegate() {
        return clientParameterDelegate;
    }

    public boolean hasProperRunDirectory() {
        if (runDirectory != null) {
            File runCommandDirectoryHandle = new File(runDirectory);
            return runCommandDirectoryHandle.isDirectory() && runCommandDirectoryHandle.canRead();
        } else {
            return false;
        }
    }

    public File getRunDirectory() {
        if (!hasProperRunDirectory()) {
            return null;
        }
        return new File(runDirectory);
    }

    public boolean hasProperLogDirectory() {
        if (logDirectory != null) {
            File runLogDirectoryHandle = new File(logDirectory);
            return runLogDirectoryHandle.isDirectory() && runLogDirectoryHandle.canWrite();
        } else {
            return false;
        }
    }

    public File getLogDirectory() {
        if (!hasProperLogDirectory()) {
            return null;
        }
        return new File(logDirectory);
    }

    public Function<State, Integer> getRunCommandExecutionCallback() {
        if(externalRunCallback != null) {
           return externalRunCallback;
        } else {
           return getRunCommandExecutionCallback(getRunCommand()); 
        }
    }

    /** Provides a callback that executes the client run command. */
    public Function<State, Integer> getRunCommandExecutionCallback(String baseCommand) {
        return (State state) -> {
            Integer serverPort = getServerDelegate().getPort();
            // port 0 = dynamic port allocation
            if (serverPort == 0) {
                serverPort = getServerPort(state.getTlsContext().getTransportHandler());
            }
            String command = baseCommand.replace(PORT_REPLACEMENT_MARKER, serverPort.toString());
            LOGGER.debug("Client run command: {}", command);
            ProcessBuilder runCommandBuilder = new ProcessBuilder(command.split(" "));
            if (hasProperRunDirectory()) {
                LOGGER.debug("Client working directory: {}", getRunDirectory().getAbsolutePath());
                runCommandBuilder.directory(getRunDirectory());
            }
            if (hasProperLogDirectory()) {
                LOGGER.debug("Client log directory: {}", getLogDirectory().getAbsolutePath());
                String fileName = System.currentTimeMillis() + CLIENT_RUN_LOG_SUFFIX;
                File logFile = new File(getLogDirectory(), fileName);
                runCommandBuilder.redirectOutput(logFile);
                runCommandBuilder.redirectError(logFile);
            }
            try {
                Process runCommandProcess = runCommandBuilder.start();
                state.addSpawnedSubprocess(runCommandProcess);
            } catch (IOException E) {
                LOGGER.error("Error during client run command execution", E);
            }
            return 0;
        };
    }

    /**
     * Retrieves the socket listening port from a given server transport handler. In case of dynamic
     * port allocation, this returns the port assigned to the server socket.
     */
    private Integer getServerPort(TransportHandler serverTransportHandler) {
        if (serverTransportHandler == null) {
            throw new RuntimeException(
                    "ServerTransportHandler was null when trying to extract server port.");
        }
        if (serverTransportHandler instanceof ServerTcpTransportHandler) {
            return ((ServerTcpTransportHandler) serverTransportHandler).getSrcPort();
        }
        if (serverTransportHandler instanceof ServerUdpTransportHandler) {
            return ((ServerUdpTransportHandler) serverTransportHandler).getSrcPort();
        }
        throw new RuntimeException(
                "Got unknown ServerTransportHandler when trying to extract server port.");
    }

    public Function<State, Integer> getExternalRunCallback() {
        return externalRunCallback;
    }

    public void setExternalRunCallback(Function<State, Integer> externalRunCallback) {
        this.externalRunCallback = externalRunCallback;
    }
}
