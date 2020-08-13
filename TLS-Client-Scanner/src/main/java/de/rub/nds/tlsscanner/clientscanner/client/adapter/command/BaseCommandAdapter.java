package de.rub.nds.tlsscanner.clientscanner.client.adapter.command;

import java.io.Serializable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsscanner.clientscanner.client.ClientInfo;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.IClientAdapter;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.ICommandExecutor;

public abstract class BaseCommandAdapter implements IClientAdapter {
    private static final Logger LOGGER = LogManager.getLogger();
    protected final ICommandExecutor executor;

    public BaseCommandAdapter(ICommandExecutor executor) {
        this.executor = executor;
    }

    @Override
    public void prepare(boolean clean) {
        this.executor.prepare(clean);
    }

    @Override
    public void cleanup(boolean deleteAll) {
        this.executor.cleanup(deleteAll);
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