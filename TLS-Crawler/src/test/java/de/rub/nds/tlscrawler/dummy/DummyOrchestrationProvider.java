/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.dummy;

import de.rub.nds.tlscrawler.data.ScanJob;
import de.rub.nds.tlscrawler.orchestration.DoneNotificationConsumer;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.orchestration.ScanJobConsumer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import org.apache.logging.log4j.Logger;

public class DummyOrchestrationProvider implements IOrchestrationProvider {
    private final Logger LOGGER = org.apache.logging.log4j.LogManager.getLogger();
    private final Thread consumerThread;

    public final BlockingQueue<ScanJob> jobQueue = new LinkedBlockingQueue<>();
    public final LinkedBlockingQueue<ScanJobConsumer> jobConsumers = new LinkedBlockingQueue<>();
    public final Map<Long, ScanJob> unackedJobs = new HashMap<>();
    public final List<DoneNotificationConsumer> doneNotificationConsumers = new ArrayList<>();
    private long jobIdCounter = 0;

    public DummyOrchestrationProvider() {
        consumerThread = new Thread(this::consumerThreadTask);
        consumerThread.start();
    }

    private void consumerThreadTask() {
        while (true) {
            try {
                // pick consumers round-robin, probably not the most efficient implementation, but
                // this is just for testing
                ScanJobConsumer consumer = jobConsumers.take();
                ScanJob scanJob = jobQueue.take();
                jobConsumers.put(consumer);
                long id = jobIdCounter++;
                unackedJobs.put(id, scanJob);
                LOGGER.info("Sending job {} to consumer as ID {}", scanJob, id);
                consumer.consumeScanJob(scanJob, id);
            } catch (InterruptedException e) {
                break;
            }
        }
    }

    @Override
    public void submitScanJob(ScanJob scanJob) {
        LOGGER.info("Received job {}", scanJob);
        jobQueue.add(scanJob);
    }

    @Override
    public void registerScanJobConsumer(ScanJobConsumer scanJobConsumer, int prefetchCount) {
        jobConsumers.add(scanJobConsumer);
    }

    @Override
    public void registerDoneNotificationConsumer(
            DoneNotificationConsumer doneNotificationConsumer) {
        doneNotificationConsumers.add(doneNotificationConsumer);
    }

    @Override
    public void notifyOfDoneScanJob(ScanJob scanJob) {
        LOGGER.info("Job {} ID={} was acked", scanJob, scanJob.getDeliveryTag());
        unackedJobs.remove(scanJob.getDeliveryTag());
        for (DoneNotificationConsumer consumer : doneNotificationConsumers) {
            consumer.consumeDoneNotification(null, scanJob);
        }
    }

    @Override
    public void closeConnection() {
        consumerThread.interrupt();
    }
}
