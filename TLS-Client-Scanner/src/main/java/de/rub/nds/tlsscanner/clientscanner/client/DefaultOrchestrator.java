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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.CloseableThreadContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsscanner.clientscanner.Server;
import de.rub.nds.tlsscanner.clientscanner.client.adapter.ClientAdapter;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.config.modes.ScanClientCommandConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.ControlledClientDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.ControlledClientDispatcher.ClientProbeResultFuture;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.Dispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIFallingBackDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIUidDispatcher;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SNIProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SNIProbe.SNIProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientAdapterResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.util.helper.BaseFuture;
import de.rub.nds.tlsscanner.clientscanner.util.helper.SyncObjectPool;
import de.rub.nds.tlsscanner.clientscanner.util.helper.SyncObjectPool.SyncObject;

public class DefaultOrchestrator implements Orchestrator {
    private static final int CLIENT_RETRY_COUNT = 5;
    private static final Logger LOGGER = LogManager.getLogger();

    protected final SyncObjectPool syncObjectPool = new SyncObjectPool();
    protected final ClientAdapter clientAdapter;
    protected final Server server;
    protected final ControlledClientDispatcher ccDispatcher;
    protected final ClientScannerConfig csConfig;
    protected final ExecutorService secondaryExecutor;

    protected String baseHostname;

    public DefaultOrchestrator(ClientScannerConfig csConfig, ExecutorService secondaryExecutor, int serverThreads) {
        this.csConfig = csConfig;
        ScanClientCommandConfig scanCfg = csConfig.getSelectedSubcommand(ScanClientCommandConfig.class);
        clientAdapter = scanCfg.createClientAdapter();
        baseHostname = csConfig.getServerBaseURL();
        LOGGER.info("Using base hostname {}", baseHostname);

        SNIDispatcher sniD = new SNIDispatcher();
        ccDispatcher = new ControlledClientDispatcher();
        sniD.registerRule(baseHostname, sniD);
        sniD.registerRule("uid", new SNIUidDispatcher());
        sniD.registerRule("cc", ccDispatcher);
        server = new Server(csConfig, new SNIFallingBackDispatcher(sniD, ccDispatcher), serverThreads);
        this.secondaryExecutor = secondaryExecutor;
    }

    @Override
    public ExecutorService getSecondaryExecutor() {
        return secondaryExecutor;
    }

    @Override
    public ClientScannerConfig getCSConfig() {
        return csConfig;
    }

    @Override
    public ClientInfo getReportInformation() {
        return clientAdapter.getReportInformation();
    }

    @Override
    public void start() {
        server.start();
        clientAdapter.prepare();
    }

    @Override
    public void cleanup() {
        server.kill();
        clientAdapter.cleanup();
    }

    private ClientProbeResult runDispatcher(Dispatcher dispatcher, String hostnamePrefix, String hostname,
            ClientReport report, Object additionalParameters)
            throws InterruptedException, ExecutionException {
        FutureClientAdapterResult clientResultHolder = new FutureClientAdapterResult();

        ClientProbeResultFuture serverResultFuture;
        // we need to sync enqueueing and connecting per unique hostname
        // TODO improve this, such that we can unsync as soon as we got a
        // connection
        // this requires us to change the client adapter interface
        // unfortunately...
        String syncHostname = null;
        if (report.hasResult(SNIProbe.class) && report.getResult(SNIProbe.class, SNIProbeResult.class).supported) {
            // if the client supports SNI we will only sync per hostname
            // otherwise we sync on null - i.e. "globally" per Orchestrator
            // TODO a "smart" orchestrator
            // if we detect that SNI is not supported we should fall
            // back to a thread local approach
            // should:tm: be relatively easy to implement using the
            // ThreadLocalOrchestrator and this Orchestrator class
            syncHostname = hostname;
        }
        try (SyncObject _sync = syncObjectPool.get(syncHostname)) {
            // enqueue probe on serverside
            serverResultFuture = ccDispatcher.enqueueDispatcher(dispatcher, hostnamePrefix, report.uid, hostname,
                    clientResultHolder, report, additionalParameters);

            // tell client to connect and get its result
            ClientAdapterResult clientResult = null;
            int tryNo = 0;
            try {
                while (!serverResultFuture.isGotConnection()) {
                    // sleep a bit after fails
                    if (tryNo + 1 >= CLIENT_RETRY_COUNT) {
                        LOGGER.warn("Failed to get connection from client after {} tries", CLIENT_RETRY_COUNT);
                        break;
                    }
                    Thread.sleep(1000 * tryNo);
                    tryNo++;
                    // assume that connect runs synchronously
                    LOGGER.trace("Running client probe (try: {})", tryNo);
                    clientResult = clientAdapter.connect(hostname, server.getPort());
                    LOGGER.trace("Client is done running probe - check whether server got connection");
                }
                LOGGER.trace("Done running client");
                clientResultHolder.setResult(clientResult);
            } catch (Exception e) {
                clientResultHolder.setException(e);
                throw e;
            }
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

    @Override
    public ClientProbeResult runDispatcher(Dispatcher probe, String hostnamePrefix, ClientReport report,
            Object additionalParameters)
            throws InterruptedException, ExecutionException {
        String hostname = String.format("%s.cc.%s.uid.%s", hostnamePrefix, report.uid, baseHostname);
        try (final CloseableThreadContext.Instance ctc = CloseableThreadContext.push(hostname)) {
            return runDispatcher(probe, hostnamePrefix, hostname, report, additionalParameters);
        }
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