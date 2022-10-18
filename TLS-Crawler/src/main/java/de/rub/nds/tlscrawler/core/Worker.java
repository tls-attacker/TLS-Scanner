/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.config.WorkerCommandConfig;
import de.rub.nds.tlscrawler.orchestration.RabbitMqOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.scans.PingScan;
import de.rub.nds.tlscrawler.scans.Scan;
import de.rub.nds.tlscrawler.scans.TlsScan;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.concurrent.*;

/**
 * Worker that subscribe to scan job queue, initializes thread pool and submits received scan jobs to thread pool.
 */
public class Worker extends TlsCrawler {

    private static final Logger LOGGER = LogManager.getLogger();

    private final int maxThreadCount;
    private final int parallelProbeThreads;
    private final int scanTimeout;

    private final ThreadPoolExecutor executor;
    private final ThreadPoolExecutor timeoutExecutor;

    /**
     * TLS-Crawler constructor.
     *
     * @param commandConfig
     *                              The config for this worker.
     * @param orchestrationProvider
     *                              A non-null orchestration provider.
     * @param persistenceProvider
     *                              A non-null persistence provider.
     *
     */
    public Worker(WorkerCommandConfig commandConfig, RabbitMqOrchestrationProvider orchestrationProvider, IPersistenceProvider persistenceProvider) {
        super(orchestrationProvider, persistenceProvider);
        this.maxThreadCount = commandConfig.getNumberOfThreads();
        this.parallelProbeThreads = commandConfig.getParallelProbeThreads();
        this.scanTimeout = commandConfig.getScanTimeout();

        executor = new ThreadPoolExecutor(maxThreadCount, maxThreadCount, 5, TimeUnit.MINUTES, new LinkedBlockingDeque<>());
        timeoutExecutor = new ThreadPoolExecutor(maxThreadCount, maxThreadCount, 5, TimeUnit.MINUTES, new LinkedBlockingDeque<>());
    }

    public void start() {
        this.orchestrationProvider.registerScanJobConsumer(((scanJob, deliveryTag) -> {
            switch (scanJob.getScanConfig().getScanType()) {
                case TLS:
                    this.submitWithTimeout(new TlsScan(scanJob, deliveryTag, orchestrationProvider, persistenceProvider, parallelProbeThreads));
                    break;
                case PING:
                    this.submitWithTimeout(new PingScan(scanJob, deliveryTag, orchestrationProvider, persistenceProvider));
                    break;
            }
        }), this.maxThreadCount);
    }

    private void submitWithTimeout(Scan scan) {
        timeoutExecutor.submit(() -> {
            Future<?> future = null;
            try {
                future = executor.submit(scan);
                future.get(this.scanTimeout, TimeUnit.MILLISECONDS);
            } catch (InterruptedException | ExecutionException e) {
                LOGGER.error("Could not submit a scan to the worker thread with error ", e);
            } catch (TimeoutException e) {
                LOGGER.info("Trying to shutdown scan of '{}' because timeout reached", scan.getScanJob().getScanTarget());
                scan.cancel(true);
                future.cancel(true);
            }
        });
    }
}
