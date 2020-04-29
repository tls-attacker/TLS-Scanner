/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.config.MasterCommandConfig;
import de.rub.nds.tlscrawler.data.ScanJob;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author robert
 */
public class Master {

    private static final Logger LOGGER = LogManager.getLogger();

    private IOrchestrationProvider orchestrationProvider;
    private MasterCommandConfig config;

    public Master(MasterCommandConfig config, IOrchestrationProvider orchestrationProvider) {
        this.orchestrationProvider = orchestrationProvider;
        this.config = config;
    }

    public void start() {
        cleanUpFinishedScanTasks();
        int counter = 0;
        do {
            ScanJob job = new ScanJob(config.getScanName(), config.getScanName() + "-" + counter, "tls", config.getPort(), config.getReexecutions(), config.getScannerTimeout());
            addFreshScanTasks(job);
            orchestrationProvider.putScanJob(job);
            counter++;
            if (checkForEarlyAbortion(counter)) {
                break;
            }
            waitTillScanJobFinishes(job);
            cleanUpFinishedScanTasks();
            waitAfterFinishedScan(config.getWaitTimeAfterScan());
        } while (counter < config.getScansToBeExecuted() || config.getScansToBeExecuted() == 0);
        LOGGER.info("All scans queued up. Shutting master down");
    }

    private void addFreshScanTasks(ScanJob job) throws RuntimeException {
        List<String> hostNameList = new LinkedList<>();
        try {
            BufferedReader reader = new BufferedReader(new FileReader(new File(config.getHostFile())));
            String line;
            while ((line = reader.readLine()) != null) {
                hostNameList.add(line);
            }
        } catch (IOException ex) {
            throw new RuntimeException("Could not load " + config.getHostFile(), ex);
        }
        orchestrationProvider.addScanTasks(job, hostNameList);
    }

    private boolean checkForEarlyAbortion(int counter) {
        if (counter > config.getScansToBeExecuted() && config.getScansToBeExecuted() != 0) {
            return true;
        }
        return false;
    }

    private void waitTillScanJobFinishes(ScanJob job) {
        LOGGER.info("Waiting till ScanJob finishes - this may take hours, days, weeks, months - depending on the schedules scan - see you then :)");

        while (orchestrationProvider.getNumberOfTasks(job) > 0) {
            try {
                Thread.currentThread().sleep(60000);
            } catch (InterruptedException ex) {
                LOGGER.error("Error during sleeping :(");
            }
        }
    }

    private void waitAfterFinishedScan(long minutes) {
        LOGGER.info("Giving the hosts that should be scanned a break of " + minutes + " minutes");
        try {
            Thread.currentThread().sleep(minutes * 60000);
        } catch (InterruptedException ex) {
            LOGGER.error("Error during sleeping :(");
        }
    }

    private void cleanUpFinishedScanTasks() {
        LOGGER.info("Looking for already finished ScanJobs in the Queue");
        Collection<ScanJob> scanJobs = orchestrationProvider.getScanJobs();
        for (ScanJob job : scanJobs) {
            if (orchestrationProvider.getNumberOfTasks(job) == 0) {
                LOGGER.info("Found an already finished ScanJobs. Deleting");
                orchestrationProvider.deleteScanJob(job);
            }
        }
    }
}
