/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.PersistenceProviderStats;
import de.rub.nds.tlscrawler.orchestration.IOrchestrationProvider;
import de.rub.nds.tlscrawler.persistence.IPersistenceProvider;
import de.rub.nds.tlscrawler.scans.IScan;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Contains test cases for the TLSCrawler base class.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TLSCrawlerTest {
    private TLSCrawler subject;

    @Before
    public void setUp() throws Exception {
        IPersistenceProvider pp = mock(IPersistenceProvider.class);
        when(pp.getStats()).thenReturn(new PersistenceProviderStats(15, 10, null, null));

        IOrchestrationProvider op = mock(IOrchestrationProvider.class);
        when(op.getScanTask()).thenReturn("scanTaskId");

        IScan scan1 = mock(IScan.class);
        when(scan1.getName()).thenReturn("Scan1");

        IScan scan3 = mock(IScan.class);
        when(scan3.getName()).thenReturn("Scan3");

        List<IScan> scans = Arrays.asList(scan1, scan3);

        this.subject = new TLSCrawler(op, pp, scans);
    }

    @Test
    public void getOrchestrationProvider() throws Exception {
        IOrchestrationProvider op = this.subject.getOrchestrationProvider();

        Assert.assertNotNull(op);
        Assert.assertEquals("scanTaskId", op.getScanTask());
    }

    @Test
    public void getPersistenceProvider() throws Exception {
        IPersistenceProvider pp = this.subject.getPersistenceProvider();

        Assert.assertNotNull(pp);
        Assert.assertEquals(15, pp.getStats().getTotalTasks());
    }

    @Test
    public void getScans() throws Exception {
        List<IScan> scans = this.subject.getScans();

        Assert.assertEquals(2, scans.size());

        List<String> scanNames = scans.stream().map(x -> x.getName()).collect(Collectors.toList());
        Assert.assertTrue(scanNames.containsAll(Arrays.asList("Scan1", "Scan3")));
    }

    @Test
    public void getScanNames() throws Exception {
        Assert.assertTrue(this.subject.getScanNames().containsAll(Arrays.asList("Scan1", "Scan3")));
        Assert.assertEquals(2, this.subject.getScanNames().size());
    }

    @Test
    public void getScanByName() throws Exception {
        Assert.assertNotNull(this.subject.getScanByName("Scan3"));
        Assert.assertNull(this.subject.getScanByName("Scan2"));
    }
}