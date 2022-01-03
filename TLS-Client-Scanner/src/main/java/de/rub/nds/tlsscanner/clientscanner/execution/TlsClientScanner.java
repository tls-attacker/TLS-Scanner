/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.execution;

import de.rub.nds.scanner.core.execution.ScanJob;
import de.rub.nds.scanner.core.execution.ThreadedScanJobExecutor;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.probe.BasicProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.DheParameterProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.ForcedCompressionProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.FreakProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.Version13RandomProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.VersionProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.execution.TlsScanner;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.function.Function;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class TlsClientScanner extends TlsScanner {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ParallelExecutor parallelExecutor;
    private final ClientScannerConfig config;
    private ServerSocket socket = null;

    public TlsClientScanner(ClientScannerConfig config, Function<State, Integer> clientAfterPreInitCallback) {
        super(config.getProbes());
        this.config = config;
        parallelExecutor = new ParallelExecutor(config.getOverallThreads(), 3);
        parallelExecutor.setDefaultBeforeTransportInitCallback(clientAfterPreInitCallback);
        parallelExecutor.setDefaultBeforeTransportPreInitCallback(createConnectionHook());
        fillDefaultProbeLists();
    }

    @Override
    protected void fillDefaultProbeLists() {
        addProbeToProbeList(new BasicProbe(parallelExecutor, config));
        addProbeToProbeList(new DheParameterProbe(parallelExecutor, config));
        addProbeToProbeList(new ForcedCompressionProbe(parallelExecutor, config));
        addProbeToProbeList(new FreakProbe(parallelExecutor, config));
        addProbeToProbeList(new Version13RandomProbe(parallelExecutor, config));
        addProbeToProbeList(new VersionProbe(parallelExecutor, config));
    }

    public ClientReport scan() {

        ThreadedScanJobExecutor executor = null;
        try {
            int port = config.getServerDelegate().getPort();
            socket = new ServerSocket(port);
            if (port == 0) {
                port = socket.getLocalPort();
                LOGGER.info("Got assigned port {}", port);
                config.getServerDelegate().setPort(port);
            }
            ScanJob job = new ScanJob(probeList, afterList);
            executor = new ThreadedScanJobExecutor(config, job, config.getParallelProbes(), "");
            ClientReport report = (ClientReport) executor.execute(new ClientReport());
            return report;
        } catch (IOException ex) {
            LOGGER.error("Could not open socket for the scanner to use (port {})",
                config.getServerDelegate().getPort());
            return new ClientReport();
        } finally {
            if (executor != null) {
                executor.shutdown();
            }
            parallelExecutor.shutdown();
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ex) {
                    LOGGER.error("Could not close server socket", ex);
                }
            }
        }
    }

    private Function<State, Integer> createConnectionHook() {
        return (State state) -> {
            try {
                state.getTlsContext().setTransportHandler(
                    new ServerTcpTransportHandler(state.getTlsContext().getConnection().getFirstTimeout(),
                        state.getTlsContext().getConnection().getTimeout(), socket));
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
            return 0;
        };
    }
}
