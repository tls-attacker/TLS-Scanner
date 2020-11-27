/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.client.adapter.command;

import java.io.Serializable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsscanner.clientscanner.client.ClientInfo;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.ClientAdapter;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.CommandExecutor;

public abstract class BaseCommandAdapter implements ClientAdapter {
    private static final Logger LOGGER = LogManager.getLogger();
    protected final CommandExecutor executor;

    public BaseCommandAdapter(CommandExecutor executor) {
        this.executor = executor;
    }

    @Override
    public void prepare() {
        this.executor.prepare();
    }

    @Override
    public void cleanup() {
        this.executor.cleanup();
    }

    @Override
    public final ClientInfo getReportInformation() {
        return new CommandClientInfo(getCommandInfo(), executor.getReportInformation());
    }

    public static class CommandClientInfo extends ClientInfo {
        public final CommandInfo command;
        public final ClientInfo executor;

        public CommandClientInfo(CommandInfo command, ClientInfo executor) {
            this.command = command;
            this.executor = executor;
        }

        @Override
        public String toShortString() {
            return String.format("%s [%s]", command.name, executor.toShortString());
        }

    }

    public static class CommandInfo implements Serializable {
        public final String name;
        public final String version;

        public CommandInfo(String name, String version) {
            this.name = name;
            this.version = version;
        }
    }

    public abstract CommandInfo getCommandInfo();
}