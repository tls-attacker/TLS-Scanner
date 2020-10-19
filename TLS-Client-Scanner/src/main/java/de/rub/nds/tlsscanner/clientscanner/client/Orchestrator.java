/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.client;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlsscanner.clientscanner.Server;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.DockerLibAdapter;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.IClientAdapter;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.CurlAdapter;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.command.executor.ProxiedLocalCommandExecutor;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.ScanClientCommandConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.ControlledClientDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.ControlledClientDispatcher.ClientProbeResultFuture;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIFallingBackDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNINopDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIUidDispatcher;
import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.util.helper.BaseFuture;

public class Orchestrator implements IOrchestrator {
    private static final int CLIENT_RETRY_COUNT = 5;
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
        // if no sni we pass null as expected hostname to dispatcher, possibly
        // also disable multithreading...
        // clientAdapter = new CurlAdapter(new LocalCommandExecutor())
        // 7.72.0--openssl-client:1.0.1
        // 7.72.0--openssl-client:1.0.2
        // 7.72.0--openssl-client:1.1.1g
        // 7.72.0--boringssl-client:master
        ScanClientCommandConfig scanCfg = csConfig.getSelectedSubcommand(ScanClientCommandConfig.class);
        clientAdapter = scanCfg.createClientAdapter();
        baseHostname = csConfig.getServerBaseURL();
        LOGGER.info("Using base hostname {}", baseHostname);

        SNIDispatcher snid = new SNIDispatcher();
        dispatcher = new ControlledClientDispatcher();
        snid.registerRule(baseHostname, new SNINopDispatcher());
        snid.registerRule("uid", new SNIUidDispatcher());
        snid.registerRule("cc", dispatcher);
        server = new Server(csConfig, new SNIFallingBackDispatcher(snid, dispatcher), 1);
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
    public ClientProbeResult runProbe(IProbe probe, String hostnamePrefix, String uid, ClientReport report)
            throws InterruptedException, ExecutionException {
        // keep track of multithreading to possibly issue warning
        if (!wasCalledWithMultithreading) {
            if (callingThread == null) {
                callingThread = Thread.currentThread();
            } else if (callingThread != Thread.currentThread()) {
                wasCalledWithMultithreading = true;
            }
        }

        String hostname = String.format("%s.cc.%s.uid.%s", hostnamePrefix, uid, baseHostname);
        FutureClientAdapterResult clientResultHolder = new FutureClientAdapterResult();
        // enqueue probe on serverside
        ClientProbeResultFuture serverResultFuture = dispatcher.enqueueProbe(probe, hostnamePrefix, uid,
                clientResultHolder, report);

        // tell client to connect and get its result
        ClientAdapterResult clientResult = null;
        int tryNo = 0;
        try {
            while (!serverResultFuture.isGotConnection()) {
                // sleep a bit after fails
                Thread.sleep(1000 * tryNo);
                if (tryNo++ >= CLIENT_RETRY_COUNT) {
                    LOGGER.warn("Failed to get connection from client after {} tries", CLIENT_RETRY_COUNT);
                    break;
                }
                // assume that connect runs synchronously
                clientResult = clientAdapter.connect(hostname, server.getPort());
            }
            clientResultHolder.setResult(clientResult);
        } catch (Exception e) {
            clientResultHolder.setException(e);
            throw e;
        }

        // wait for result from server
        ClientProbeResult res;
        if (serverResultFuture.isGotConnection()) {
            // wait indefinitely
            res = serverResultFuture.get();
        } else {
            // we did not get a connection yet, let's just give it the benefit
            // of the doubt
            // and wait for 10 more seconds
            try {
                res = serverResultFuture.get(10, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                throw new ExecutionException("Failed to get result.", e);
            }
        }
        return res;
    }

    protected static class FutureClientAdapterResult extends BaseFuture<ClientAdapterResult> {

        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            throw new UnsupportedOperationException("Not implemented");
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

    }

}