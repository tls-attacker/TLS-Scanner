package de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProxiedLocalCommandExecutor extends LocalCommandExecutor {
    private static final Logger LOGGER = LogManager.getLogger();
    private final List<String> proxyprefix;

    public ProxiedLocalCommandExecutor(List<String> proxyprefix) {
        this.proxyprefix = proxyprefix;
    }

    public ProxiedLocalCommandExecutor(String... proxyprefix) {
        this(Arrays.asList(proxyprefix));
    }

    @Override
    public ExecuteResult executeCommand(List<String> command) throws IOException, InterruptedException {
        StringBuilder innercmd = new StringBuilder();
        boolean first = true;
        innercmd.append('"');
        for (String c : command) {
            if (first) {
                first = false;
            } else {
                innercmd.append(' ');
            }
            innercmd.append('\'');
            innercmd.append(c);
            innercmd.append('\'');
        }
        innercmd.append('"');
        List<String> finalCommand = new ArrayList<>(proxyprefix.size() + 1);
        finalCommand.addAll(proxyprefix);
        finalCommand.add(innercmd.toString());
        return super.executeCommand(finalCommand);
    }

    @Override
    public ProxiedLocalSystemInfo getReportInformation() {
        return new ProxiedLocalSystemInfo((LocalSystemInfo) super.getReportInformation(), proxyprefix);
    }

    public static class ProxiedLocalSystemInfo extends LocalSystemInfo {
        public final String[] proxyCommand;

        public ProxiedLocalSystemInfo(LocalSystemInfo base, List<String> proxyprefix) {
            super(base);
            this.proxyCommand = proxyprefix.toArray(new String[] {});
        }

        @Override
        public String toShortString() {
            return String.format("%s[%s]", String.join(" ", proxyCommand), super.toShortString());
        }
    }

}