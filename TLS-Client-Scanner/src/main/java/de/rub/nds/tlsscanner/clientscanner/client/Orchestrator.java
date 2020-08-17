package de.rub.nds.tlsscanner.clientscanner.client;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import de.rub.nds.tlsscanner.clientscanner.Server;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.IClientAdapter;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.CurlAdapter;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.LocalCommandExecutor;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.ProxiedLocalCommandExecutor;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.ControlledClientDispatcher;
import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Orchestrator {
    private static final Logger LOGGER = LogManager.getLogger();
    protected final IClientAdapter clientAdapter;
    protected final Server server;
    protected final ControlledClientDispatcher dispatcher;

    public Orchestrator(ClientScannerConfig csConfig) {
        // clientAdapter = new CurlAdapter(new LocalCommandExecutor());
        clientAdapter = new CurlAdapter(new ProxiedLocalCommandExecutor("bash", "-c"));
        dispatcher = new ControlledClientDispatcher();
        server = new Server(csConfig, dispatcher);
    }

    public ClientInfo getReportInformation() {
        return clientAdapter.getReportInformation();
    }

    public void start() {
        server.start();
        clientAdapter.prepare(false);
    }

    public void cleanup() {
        server.kill();
        clientAdapter.cleanup(false);
    }

    public ClientProbeResult runProbe(IProbe probe) throws InterruptedException, ExecutionException {
        Future<ClientProbeResult> res = dispatcher.executeProbe(probe);
        String domain = "127.0.0.1.xip.io";
        String name = probe.getClass().getName();
        String PROBE_NAMESPACE = "de.rub.nds.tlsscanner.clientscanner.probe.";
        if (name.startsWith(PROBE_NAMESPACE)) {
            name = name.substring(PROBE_NAMESPACE.length());
        }
        clientAdapter.connect(name + '.' + domain, server.getPort());
        return res.get();
    }
}