/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.client.adapter.command;

import java.io.IOException;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.CommandExecutor;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.CommandExecutor.ExecuteResult;
import de.rub.nds.tlsscanner.clientscanner.config.CACertDelegate;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.result.BasicClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult.EContentShown;

public class CurlAdapter extends BaseCommandAdapter {
    private static final Logger LOGGER = LogManager.getLogger();
    private final String certPath;

    public CurlAdapter(CommandExecutor executor, ClientScannerConfig csConfig) {
        super(executor);
        this.certPath = csConfig.getDelegate(CACertDelegate.class).getCertPath();
    }

    @Override
    public ClientAdapterResult connect(String hostname, int port) throws InterruptedException {
        try {
            // --ssl-no-revoke might be required for some libraries (e.g. Schannel)
            ExecuteResult res = executor.executeCommand("curl", "-sS", "--cacert", certPath,
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
            return new BasicClientAdapterResult(res.exitCode == 0 ? EContentShown.SHOWN : EContentShown.ERROR);
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