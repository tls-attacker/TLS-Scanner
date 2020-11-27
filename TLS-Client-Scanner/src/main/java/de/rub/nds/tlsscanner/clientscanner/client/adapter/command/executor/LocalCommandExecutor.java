/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsscanner.clientscanner.client.ClientInfo;

public class LocalCommandExecutor implements CommandExecutor {
    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void prepare() {
        // nothing to prepare
    }

    @Override
    public ExecuteResult executeCommand(List<String> command) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        LOGGER.debug("Starting Command [{}]", String.join(" ", command));
        Process proc = pb.start();
        BufferedReader stdout = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        BufferedReader stderr = new BufferedReader(new InputStreamReader(proc.getErrorStream()));

        int exitCode = proc.waitFor();
        LOGGER.debug("Process exited with code {}", exitCode);
        return new ExecuteResult(exitCode, stdout, stderr);
    }

    @Override
    public void cleanup() {
        // nothing to cleanup
    }

    @Override
    public LocalSystemInfo getReportInformation() {
        return new LocalSystemInfo(System.getProperties());
    }

    public static class LocalSystemInfo extends ClientInfo {
        protected final String UNKNOWN = "unknown";
        public final String arch;
        public final String name;
        public final String version;

        public LocalSystemInfo(LocalSystemInfo toCopy) {
            this.arch = toCopy.arch;
            this.name = toCopy.name;
            this.version = toCopy.version;
        }

        public LocalSystemInfo(Properties systemProperties) {
            arch = systemProperties.getProperty("os.arch", UNKNOWN);
            name = systemProperties.getProperty("os.name", UNKNOWN);
            version = systemProperties.getProperty("os.version", UNKNOWN);
        }

        @Override
        public String toShortString() {
            return String.format("Local System/%s", name);
        }
    }

}