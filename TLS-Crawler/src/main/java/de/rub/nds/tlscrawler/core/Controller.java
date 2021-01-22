/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.config.ControllerCommandConfig;
import de.rub.nds.tlscrawler.data.ScanJob;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author robert
 */
public class Controller {

    private static final Logger LOGGER = LogManager.getLogger();

    private IOrchestrationProvider orchestrationProvider;
    private ControllerCommandConfig config;

    public Controller(ControllerCommandConfig config, IOrchestrationProvider orchestrationProvider) {
        this.orchestrationProvider = orchestrationProvider;
        this.config = config;
    }

    public void start() {
        cleanUpFinishedScanTasks();
        int counter = 0;
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDateTime now = LocalDateTime.now();
        String currentDate = dtf.format(now);
        do {
            LOGGER.info("Initializing ScanJob");
            ScanJob job = new ScanJob(config.getScanName(), config.getScanName() + "_" + currentDate + "_" + counter, "tls", config.getPort(), config.getReexecutions(), config.getScannerTimeout(), config.getStarttlsDelegate().getStarttlsType());
            addFreshScanTasks(job);
            LOGGER.info("Pushing ScanJob");
            orchestrationProvider.putScanJob(job);
            LOGGER.info("ScanJob pushed");
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
        LOGGER.info("Reading hostName list");
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
        LOGGER.info("Read " + hostNameList.size() + " hosts");
        orchestrationProvider.addScanTasks(job, hostNameList);
        LOGGER.info("Pushed scans tasks");
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
