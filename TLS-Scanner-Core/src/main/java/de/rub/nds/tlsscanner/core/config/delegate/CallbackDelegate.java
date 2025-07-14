/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.protocol.exception.ConfigurationException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.IOException;
import java.util.function.Function;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CallbackDelegate extends Delegate {

    private static final Logger LOGGER = LogManager.getLogger();

    @Parameter(
            names = "-beforeTransportPreInitCb",
            required = false,
            description =
                    "The shell command the scanner should run before the pre initialization of the transport handler.")
    private String beforeTransportPreInitCommand = null;

    @Parameter(
            names = "-beforeTransportInitCb",
            required = false,
            description =
                    "The shell command the scanner should run before the initialization of the transport handler.")
    private String beforeTransportInitCommand = null;

    @Parameter(
            names = "-afterTransportInitCb",
            required = false,
            description =
                    "The shell command the scanner should run after the initialization of the transport handler.")
    private String afterTransportInitCommand = null;

    @Parameter(
            names = "-afterExecutionCb",
            required = false,
            description = "The shell command the scanner should run after the worklfow execution.")
    private String afterExecutionCommand = null;

    public CallbackDelegate() {}

    public String getBeforeTransportPreInitCommand() {
        return beforeTransportPreInitCommand;
    }

    public String getBeforeTransportInitCommand() {
        return beforeTransportInitCommand;
    }

    public String getAfterTransportInitCommand() {
        return afterTransportInitCommand;
    }

    public String getAfterExecutionCommand() {
        return afterExecutionCommand;
    }

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {}

    public Function<State, Integer> getBeforeTransportPreInitCallback() {
        return getCallback(beforeTransportPreInitCommand);
    }

    public Function<State, Integer> getBeforeTransportInitCallback() {
        return getCallback(beforeTransportInitCommand);
    }

    public Function<State, Integer> getAfterTransportInitCallback() {
        return getCallback(afterTransportInitCommand);
    }

    public Function<State, Integer> getAfterExecutionCallback() {
        return getCallback(afterExecutionCommand);
    }

    private Function<State, Integer> getCallback(String command) {
        if (command == null) {
            return null;
        }
        return (State state) -> {
            try {
                Process spawnedProcess = Runtime.getRuntime().exec(command.split(" "));
                LOGGER.debug("Running command: {}", command);
                state.addSpawnedSubprocess(spawnedProcess);
            } catch (IOException E) {
                LOGGER.error("Error during command execution", E);
            }
            return 0;
        };
    }

    public static Function<State, Integer> mergeCallbacks(Function<State, Integer>... callbacks) {
        return (State state) -> {
            for (Function<State, Integer> callback : callbacks) {
                if (callback == null) {
                    continue;
                }
                callback.apply(state);
            }
            return 0;
        };
    }
}
