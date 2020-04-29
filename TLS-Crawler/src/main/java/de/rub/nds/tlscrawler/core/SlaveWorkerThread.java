/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.ScanTask;
import de.rub.nds.tlscrawler.scans.IScan;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.time.Instant;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

/**
 * Worker Thread for a more sophisticated TLS crawler slave implementation.
 *
 * // TODO: Graceful exit
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class SlaveWorkerThread extends Thread {

    private static Logger LOG = LogManager.getLogger();

    private final SynchronizedTaskRouter synchronizedTaskRouter;
    private final String slaveInstanceId;

    private IScanProvider scanProvider;

    public SlaveWorkerThread(String slaveInstanceId,
            SynchronizedTaskRouter synchronizedTaskRouter,
            IScanProvider scanProvider) {
        this.slaveInstanceId = slaveInstanceId;
        this.synchronizedTaskRouter = synchronizedTaskRouter;
        this.scanProvider = scanProvider;
    }

    @Override
    public void run() {
        for (;;) {
            ScanTask todo = this.synchronizedTaskRouter.getTodo();

            if (todo != null) {
                LOG.trace("Started work on {}.", todo.getId());
                this.setName("Thread - " + todo.getScanTarget());

                Document result;

                try {
                    IScan scanInstance = this.scanProvider.getCurrentScan();
                    
                    result = scanInstance.scan(todo.getScanTarget());
                } catch (Exception e) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    e.printStackTrace(new PrintStream(out));
                    String str = new String(out.toByteArray());
                    result = new Document("failedWithException", str);
                }

                todo.setResult(result);

                todo.setCompletedTimestamp(Instant.now());

                this.synchronizedTaskRouter.addFinished(todo);
            } else {
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    // Suffer quietly.
                }
            }
        }
    }
}
