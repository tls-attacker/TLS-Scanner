/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlscrawler.data.ScanJob;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlscrawler.orchestration.RabbitMqOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Instant;
import java.util.ArrayList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

/** A simple scan testing whether a host is available at a given IP address. */
public class PingScan extends Scan {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final int timeOutMs = 5000;

    public PingScan(
            ScanJob scanJob,
            long rabbitMqAckTag,
            RabbitMqOrchestrationProvider orchestrationProvider,
            IPersistenceProvider persistenceProvider) {
        super(scanJob, rabbitMqAckTag, orchestrationProvider, persistenceProvider);
    }

    // Ping, Java style. I. e., 1 of approx. 10^10 possible implementations with
    // unique advantages and disadvantages to
    // each. Yeah. Standard port: Echo service, port nr 7
    private static boolean isReachable(String address, int port) {
        LOGGER.trace("isReachable()");

        if (port < 1 || port > 65535) {
            LOGGER.error("Tried connecting to a port outside the 16-bit range.");
            throw new IllegalArgumentException("port must be in range 1-65535.");
        }

        try (Socket soc = new Socket()) {
            soc.connect(new InetSocketAddress(address, port), PingScan.timeOutMs);
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    @Override
    public void run() {
        LOGGER.trace("scan()");

        Document result = new Document();
        result.put("timestamp", Instant.now());
        result.put("timeout", timeOutMs);

        if (isReachable(scanJob.getScanTarget().getIp(), scanJob.getScanTarget().getPort())) {
            result.put("reachablePorts", new ArrayList<>(scanJob.getScanTarget().getPort()));
            result.put("unreachablePorts", new ArrayList<>());
        } else {
            result.put("reachablePorts", new ArrayList<>());
            result.put("unreachablePorts", new ArrayList<>(scanJob.getScanTarget().getPort()));
        }

        persistenceProvider.insertScanResult(
                new ScanResult(scanJob.getBulkScanId(), scanJob.getScanTarget(), result),
                scanJob.getDbName(),
                scanJob.getCollectionName());

        if (scanJob.isMonitored()) {
            orchestrationProvider.notifyOfDoneScanJob(scanJob);
        }
    }
}
