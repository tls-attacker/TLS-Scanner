package de.rub.nds.tlsscanner.clientscanner.client;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlsscanner.clientscanner.Server;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.ClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.DockerLibAdapter;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.IClientAdapter;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.ControlledClientDispatcher;
import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class Orchestrator implements IOrchestrator {
    private static final Logger LOGGER = LogManager.getLogger();
    protected final IClientAdapter clientAdapter;
    protected final Server server;
    protected final ControlledClientDispatcher dispatcher;

    private Thread callingThread = null;
    private boolean wasCalledWithMultithreading = false;
    protected String baseHostname = "127.0.0.1.xip.io";

    public Orchestrator(ClientScannerConfig csConfig) {
        // TODO (create and) handle SNI flag in config
        // if sni do as it is now
        // if no sni we pass null as expected hostname to dispatcher, possibly also
        // disable multithreading...
        // clientAdapter = new CurlAdapter(new LocalCommandExecutor())
        clientAdapter = new DockerLibAdapter(TlsImplementationType.CURL, "7.72.0--openssl-client:1.1.1g");
        if (clientAdapter instanceof DockerLibAdapter) {
            baseHostname = "192.168.65.2.xip.io"; // windows, for my machine
            // TODO move baseHostname into config
        }

        dispatcher = new ControlledClientDispatcher();
        server = new Server(csConfig, dispatcher, 1);
    }

    @Override
    public ClientInfo getReportInformation() {
        return clientAdapter.getReportInformation();
    }

    @Override
    public void start() {
        server.start();
        clientAdapter.prepare(false);
    }

    @Override
    public void cleanup() {
        server.kill();
        clientAdapter.cleanup(false);
    }

    @Override
    public void postProcessing(ClientReport report) {
        if (dispatcher.isPrintedNoSNIWarning() && wasCalledWithMultithreading) {
            report.addGenericWarning(
                    "Client made unexpected connections without an SNI extension. This may cause issues, as the probes and hostnames might not match due to multithreading.");
        }
    }

    @Override
    public ClientProbeResult runProbe(IProbe probe)
            throws InterruptedException, ExecutionException {
        String name = probe.getClass().getName();
        String PROBE_NAMESPACE = "de.rub.nds.tlsscanner.clientscanner.probe.";
        if (name.startsWith(PROBE_NAMESPACE)) {
            name = name.substring(PROBE_NAMESPACE.length());
        }
        return runProbe(probe, name);
    }

    @Override
    public ClientProbeResult runProbe(IProbe probe, String hostnamePrefix)
            throws InterruptedException, ExecutionException {
        // keep track of multithreading to possibly issue warning
        if (!wasCalledWithMultithreading) {
            if (callingThread == null) {
                callingThread = Thread.currentThread();
            } else if (callingThread != Thread.currentThread()) {
                wasCalledWithMultithreading = true;
            }
        }

        String hostname = String.format("%s.%s", hostnamePrefix, baseHostname);
        Future<ClientProbeResult> res = dispatcher.enqueueProbe(probe, hostname);
        ClientAdapterResult cres = clientAdapter.connect(hostname, server.getPort());
        // TODO! feed cres into res
        return res.get();
    }

}