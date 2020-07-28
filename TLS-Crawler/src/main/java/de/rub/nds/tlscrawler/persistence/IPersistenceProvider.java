/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.persistence;

import com.mongodb.client.DistinctIterable;
import com.mongodb.client.FindIterable;
import de.rub.nds.tlscrawler.data.IPersistenceProviderStats;

import de.rub.nds.tlscrawler.data.ScanTask;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.Collection;
import java.util.List;
import org.bson.conversions.Bson;

/**
 * Persistence provider interface. Exposes methods to write out the different
 * stages of a task to a file/database/api.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public interface IPersistenceProvider {

    public void clean(String database, String workspace);

    /**
     * Accepts new scan task. ID may or may not be set.
     *
     * @param newTask The new scan task.
     */
    public void insertScanTask(ScanTask newTask);

    /**
     * Accepts new scan tasks. IDs may or may not be set.
     *
     * @param newTasks The new scan tasks.
     */
    public void insertScanTasks(List<ScanTask> newTasks);

    /**
     * Provides information about created tasks.
     *
     * @return The stats of this persistence provider.
     */
    public IPersistenceProviderStats getStats();
    
    public long countDocuments(String database, String workspace, Bson query);

    public DistinctIterable findDistinctValues(String database, String workspace, String fieldName, Class resultClass);
    
    public FindIterable<ScanTask> findDocuments(String database, String workspace, Bson findQuery);

    public Collection<SiteReport> findSiteReports(String database, String workspace, Bson findQuery);
}
