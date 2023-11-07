/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.persistence;

import de.rub.nds.tlscrawler.data.BulkScan;
import de.rub.nds.tlscrawler.data.ScanResult;

/**
 * Persistence provider interface. Exposes methods to write out the different stages of a task to a
 * file/database/api.
 */
public interface IPersistenceProvider {

    /**
     * Insert a scan result into the database.
     *
     * @param scanResult The scan result to insert.
     * @param dbName The name of the database.
     * @param collectionName The name of the collection.
     */
    void insertScanResult(ScanResult scanResult, String dbName, String collectionName);

    /**
     * Insert a bulk scan into the database. This is used to store metadata about the bulk scan.
     * This adds an ID to the bulk scan.
     *
     * @param bulkScan The bulk scan to insert.
     */
    void insertBulkScan(BulkScan bulkScan);

    /**
     * Update a bulk scan in the database. This updated the whole bulk scan.
     *
     * @param bulkScan The bulk scan to update.
     */
    void updateBulkScan(BulkScan bulkScan);
}
