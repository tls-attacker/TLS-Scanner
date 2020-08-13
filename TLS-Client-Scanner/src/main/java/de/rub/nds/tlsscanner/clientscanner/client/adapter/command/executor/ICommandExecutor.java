package de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import de.rub.nds.tlsscanner.clientscanner.client.ClientInfo;

public interface ICommandExecutor {
    public void prepare(boolean clean);

    public default ExecuteResult executeCommand(String... command) throws IOException, InterruptedException {
        return executeCommand(Arrays.asList(command));
    }

    public ExecuteResult executeCommand(List<String> command) throws IOException, InterruptedException;

    public void cleanup(boolean deleteAll);

    public ClientInfo getReportInformation();

    public static class ExecuteResult {
        public final int exitCode;
        public final BufferedReader stdout;
        public final BufferedReader stderr;

        public ExecuteResult(int exitCode, BufferedReader stdout, BufferedReader stderr) {
            this.exitCode = exitCode;
            this.stdout = stdout;
            this.stderr = stderr;
        }
    }
}