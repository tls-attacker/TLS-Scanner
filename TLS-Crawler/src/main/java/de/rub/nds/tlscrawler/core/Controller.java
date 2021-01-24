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
import lombok.extern.log4j.Log4j2;

/**
 * @author robert
 */
@Log4j2
public class Controller {

    private final IOrchestrationProvider orchestrationProvider;
    private final ControllerCommandConfig config;

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
            log.info("Initializing ScanJob");
            ScanJob job = new ScanJob(config.getScanName(), config.getScanName() + "_" + currentDate + "_" + counter, "tls", config.getPort(), config.getReexecutions(), config.getScannerTimeout(), config.getStarttlsDelegate().getStarttlsType());
            addFreshScanTasks(job);
            log.info("Pushing ScanJob");
            orchestrationProvider.putScanJob(job);
            log.info("ScanJob pushed");
            counter++;
            if (checkForEarlyAbortion(counter)) {
                break;
            }
            waitTillScanJobFinishes(job);
            cleanUpFinishedScanTasks();
            waitAfterFinishedScan(config.getWaitTimeAfterScan());
        } while (counter < config.getScansToBeExecuted() || config.getScansToBeExecuted() == 0);
        log.info("All scans queued up. Shutting master down");
    }

    private void addFreshScanTasks(ScanJob job) throws RuntimeException {
        log.info("Reading hostName list");
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
        log.info("Read " + hostNameList.size() + " hosts");
        orchestrationProvider.addScanTasks(job, hostNameList);
        log.info("Pushed scans tasks");
    }

    private boolean checkForEarlyAbortion(int counter) {
        return counter > config.getScansToBeExecuted() && config.getScansToBeExecuted() != 0;
    }

    private void waitTillScanJobFinishes(ScanJob job) {
        log.info("Waiting till ScanJob finishes - this may take hours, days, weeks, months - depending on the schedules scan - see you then :)");

        while (orchestrationProvider.getNumberOfTasks(job) > 0) {
            try {
                Thread.sleep(60000);
            } catch (InterruptedException ex) {
                log.error("Error during sleeping :(");
            }
        }
    }

    private void waitAfterFinishedScan(long minutes) {
        log.info("Giving the hosts that should be scanned a break of " + minutes + " minutes");
        try {
            Thread.sleep(minutes * 60000);
        } catch (InterruptedException ex) {
            log.error("Error during sleeping :(");
        }
    }

    private void cleanUpFinishedScanTasks() {
        log.info("Looking for already finished ScanJobs in the Queue");
        Collection<ScanJob> scanJobs = orchestrationProvider.getScanJobs();
        for (ScanJob job : scanJobs) {
            if (orchestrationProvider.getNumberOfTasks(job) == 0) {
                log.info("Found an already finished ScanJobs. Deleting");
                orchestrationProvider.deleteScanJob(job);
            }
        }
    }
}
