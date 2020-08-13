package de.rub.nds.tlsscanner.clientscanner.client.adapter.command;

import java.io.IOException;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsscanner.clientscanner.client.adapter.ClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.ICommandExecutor;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.ICommandExecutor.ExecuteResult;

public class CurlAdapter extends BaseCommandAdapter {
    private static final Logger LOGGER = LogManager.getLogger();

    public CurlAdapter(ICommandExecutor executor) {
        super(executor);
    }

    @Override
    public ClientAdapterResult connect(String hostname, int port) throws InterruptedException {
        try {
            ExecuteResult res = executor.executeCommand("curl", "-sS", "-k",
                    String.format("https://%s:%d/", hostname, port));
            if (LOGGER.isDebugEnabled()) {
                while (res.stdout.ready()) {
                    LOGGER.debug(res.stdout.readLine());
                }
                if (res.exitCode != 0) {
                    LOGGER.debug("##STDERR##");
                    while (res.stderr.ready()) {
                        LOGGER.debug(res.stderr.readLine());
                    }
                }
            }
        } catch (IOException e) {
            LOGGER.error(e);
        }
        return null;
    }

    @Override
    public CommandInfo getCommandInfo() {
        String version = "unknown";
        try {
            ExecuteResult versionInfo;
            versionInfo = executor.executeCommand("curl", "-V");
            if (versionInfo.exitCode != 0) {
                if (LOGGER.isWarnEnabled()) {
                    LOGGER.warn("Could not get curl version information:");
                    while (versionInfo.stderr.ready()) {
                        LOGGER.warn(versionInfo.stderr.readLine());
                    }
                }
            } else {
                version = versionInfo.stdout.lines().collect(Collectors.joining());
            }
        } catch (IOException e) {
            LOGGER.error("Could not get curl version information (exception occurred)", e);
        } catch (InterruptedException e) {
            LOGGER.error("Could not get curl version information (interrupt occurred)", e);
            Thread.currentThread().interrupt();
        }
        return new CommandInfo("curl", version);
    }

}