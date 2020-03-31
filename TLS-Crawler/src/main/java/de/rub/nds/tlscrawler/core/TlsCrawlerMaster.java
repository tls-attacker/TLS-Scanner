/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.*;
import de.rub.nds.tlscrawler.scans.IScan;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.utility.IAddressIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;


/**
 * Implements Scan Task Creation.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TlsCrawlerMaster extends TlsCrawler {

    private static Logger LOG = LoggerFactory.getLogger(TlsCrawlerMaster.class);
    private static long TIME_TO_WAIT = 1;

    /**
     * TLS-Crawler master constructor.
     *
     * @param instanceId The identifier of this instance.
     * @param orchestrationProvider A non-null orchestration provider.
     * @param persistenceProvider A non-null persistence provider.
     * @param scans A neither null nor empty list of available scans.
     */
    public TlsCrawlerMaster(String instanceId,
            IOrchestrationProvider orchestrationProvider,
            IPersistenceProvider persistenceProvider,
            List<IScan> scans, int port) {
        super(instanceId, orchestrationProvider, persistenceProvider, scans, port);
    }

    
    public void crawl(List<String> scans, IAddressIterator targets, List<Integer> ports, String scanId) {
        LOG.info("Crawling started");

        try {
            while (this.getOrchestrationProvider().getNumberOfTasks() != 0) {
                TimeUnit.SECONDS.sleep(TIME_TO_WAIT);
            }
        } catch (Exception e) {
            LOG.debug("Oops! Exception", e);
        } finally {
            targets.remove();
        }
        LOG.info("All ScanTasks have been scheduled");
    }

    private static void setUp(IOrganizer org, List<ScanTask> tasks) {
        org.getPersistenceProvider().insertScanTasks(tasks);

        Collection<String> tids = tasks.stream()
                .map(x -> x.getId())
                .collect(Collectors.toList());

        org.getOrchestrationProvider().addScanTasks(tids);
    }

    public IMasterStats getStats() {
        LOG.trace("getStats()");

        IPersistenceProviderStats ppStats = this.getPersistenceProvider().getStats();

        return new MasterStats(ppStats.getTotalTasks(),
                ppStats.getFinishedTasks(),
                ppStats.getEarliestCompletionTimestamp(),
                ppStats.getEarliestCreatedTimestamp());
    }
}
