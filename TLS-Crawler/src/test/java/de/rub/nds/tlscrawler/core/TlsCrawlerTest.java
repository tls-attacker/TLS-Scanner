/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.PersistenceProviderStats;
import de.rub.nds.tlscrawler.data.ScanJob;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.LinkedList;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Contains test cases for the TlsCrawler base class.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TlsCrawlerTest {

    private TlsCrawler subject;

    private ScanJob testJob;

    @Before
    public void setUp() {
        testJob = new ScanJob("name", "workspace", "scan", 0, 0, 0);
        List<ScanJob> scanJobList = new LinkedList<>();
        scanJobList.add(testJob);
        IPersistenceProvider pp = mock(IPersistenceProvider.class);
        when(pp.getStats()).thenReturn(new PersistenceProviderStats(15, 10, null, null));

        IOrchestrationProvider op = mock(IOrchestrationProvider.class);
        when(op.getScanTask(testJob)).thenReturn("scanTaskId");
        when(op.getScanJobs()).thenReturn(scanJobList);
        when(op.getScanJobs()).thenReturn(scanJobList);
        this.subject = new TlsCrawlerSlave("slaveId", op, pp, 1);
    }

    @Test
    public void getOrchestrationProvider() {
        IOrchestrationProvider op = this.subject.getOrchestrationProvider();

        Assert.assertNotNull(op);
        Assert.assertEquals("scanTaskId", op.getScanTask(testJob));
    }

    @Test
    public void getPersistenceProvider() {
        IPersistenceProvider pp = this.subject.getPersistenceProvider();

        Assert.assertNotNull(pp);
        Assert.assertEquals(15, pp.getStats().getTotalTasks());
    }

}
