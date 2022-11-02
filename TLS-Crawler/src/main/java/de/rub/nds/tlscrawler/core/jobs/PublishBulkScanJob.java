/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.core.jobs;

import de.rub.nds.tlscrawler.config.ControllerCommandConfig;
import de.rub.nds.tlscrawler.constant.Status;
import de.rub.nds.tlscrawler.core.ProgressMonitor;
import de.rub.nds.tlscrawler.data.BulkScan;
import de.rub.nds.tlscrawler.data.ScanConfig;
import de.rub.nds.tlscrawler.data.ScanJob;
import de.rub.nds.tlscrawler.data.ScanTarget;
import de.rub.nds.tlscrawler.denylist.IDenylistProvider;
import de.rub.nds.tlscrawler.orchestration.RabbitMqOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.targetlist.ITargetListProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.quartz.Job;
import org.quartz.JobDataMap;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;

import java.util.List;
import java.util.Objects;

public class PublishBulkScanJob implements Job {

    private static final Logger LOGGER = LogManager.getLogger();

    public void execute(JobExecutionContext context) throws JobExecutionException {
        try {
            JobDataMap data = context.getMergedJobDataMap();

            ControllerCommandConfig controllerConfig = (ControllerCommandConfig) data.get("config");
            RabbitMqOrchestrationProvider orchestrationProvider = (RabbitMqOrchestrationProvider) data.get("orchestrationProvider");
            IPersistenceProvider persistenceProvider = (IPersistenceProvider) data.get("persistenceProvider");
            ITargetListProvider targetListProvider = (ITargetListProvider) data.get("targetListProvider");
            IDenylistProvider denylistProvider = (IDenylistProvider) data.get("denylistProvider");
            ProgressMonitor progressMonitor = (ProgressMonitor) data.get("progressMonitor");

            ScanConfig scanConfig = new ScanConfig(controllerConfig.getScanType(), controllerConfig.getPort(), controllerConfig.getScanDetail(), controllerConfig.getReexecutions(),
                controllerConfig.getScannerTimeout(), controllerConfig.getStarttlsDelegate().getStarttlsType());

            // Create Bulk Scan and write to DB
            LOGGER.info("Initializing BulkScan");
            BulkScan bulkScan =
                new BulkScan(controllerConfig.getScanName(), scanConfig, System.currentTimeMillis(), controllerConfig.isMonitored(), controllerConfig.getNotifyUrl());

            List<String> targetStringList = targetListProvider.getTargetList();
            bulkScan.setTargetsGiven(targetStringList.size());

            persistenceProvider.insertBulkScan(bulkScan);
            LOGGER.info("Persisted BulkScan with id: {}", bulkScan.get_id());

            if (controllerConfig.isMonitored()) {
                progressMonitor.startMonitoringBulkScanProgress(bulkScan);
            }

            // create and submit scan jobs for valid hosts
            LOGGER.info("Filtering out denylisted hosts and hosts where the domain can not be resolved.");
            long submittedJobs = targetStringList.parallelStream().map(targetString -> {
                ScanTarget target = ScanTarget.fromTargetString(targetString, controllerConfig.getPort(), denylistProvider);
                if (target != null) {
                    orchestrationProvider
                        .submitScanJob(new ScanJob(target, scanConfig, bulkScan.get_id(), bulkScan.isMonitored(), bulkScan.getName(), bulkScan.getCollectionName(), Status.Ready));
                }
                return target;
            }).filter(Objects::nonNull).count();

            bulkScan.setScanJobsPublished((int) submittedJobs);
            persistenceProvider.updateBulkScan(bulkScan);

            if (controllerConfig.isMonitored() && submittedJobs == 0) {
                progressMonitor.stopMonitoringAndFinalizeBulkScan(bulkScan.get_id());
            }
            LOGGER.info("Submitted {} scan jobs to RabbitMq", submittedJobs);
        } catch (Exception e) {
            LOGGER.error("Exception while publishing BulkScan: ", e);
            JobExecutionException e2 = new JobExecutionException(e);
            e2.setUnscheduleAllTriggers(true);
            throw e2;
        }
    }

}
