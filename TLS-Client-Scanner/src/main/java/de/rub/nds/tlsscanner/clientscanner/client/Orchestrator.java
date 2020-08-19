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
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Orchestrator {
    private static final Logger LOGGER = LogManager.getLogger();
    protected final IClientAdapter clientAdapter;
    protected final Server server;
    protected final ControlledClientDispatcher dispatcher;

    public Orchestrator(ClientScannerConfig csConfig) {
        // TODO (create and) handle SNI flag in config
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

    public void postProcessing(ClientReport report) {
        if (dispatcher.isPrintedNoSNIWarning()) {
            report.addGenericWarning(
                    "Client made unexpected connections without an SNI extension. This may cause issues when using multithreaded execution, as the probes and hostnames might not match.");
        }
    }

    public ClientProbeResult runProbe(IProbe probe) throws InterruptedException, ExecutionException {
        String name = probe.getClass().getName();
        String PROBE_NAMESPACE = "de.rub.nds.tlsscanner.clientscanner.probe.";
        if (name.startsWith(PROBE_NAMESPACE)) {
            name = name.substring(PROBE_NAMESPACE.length());
        }
        return runProbe(probe, name);
    }

    public ClientProbeResult runProbe(IProbe probe, String hostnamePrefix)
            throws InterruptedException, ExecutionException {
        String hostname = String.format("%s.%s", hostnamePrefix, "127.0.0.1.xip.io");
        Future<ClientProbeResult> res = dispatcher.enqueueProbe(probe, hostname);
        clientAdapter.connect(hostname, server.getPort());
        return res.get();
    }

}