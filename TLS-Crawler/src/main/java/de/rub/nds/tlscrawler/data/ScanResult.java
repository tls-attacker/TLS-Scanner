/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.bson.Document;

import java.io.Serializable;
import java.util.UUID;

public class ScanResult implements Serializable {

    private String id;

    private final String bulkScan;

    private final ScanTarget scanTarget;

    private final Document result;

    public ScanResult(String bulkScan, ScanTarget scanTarget, Document result) {
        this.id = UUID.randomUUID().toString();
        this.bulkScan = bulkScan;
        this.scanTarget = scanTarget;
        this.result = result;
    }

    @JsonProperty("_id")
    public String getId() {
        return this.id;
    }

    @JsonProperty("_id")
    public void setId(String id) {
        this.id = id;
    }

    public String getBulkScan() {
        return this.bulkScan;
    }

    public ScanTarget getScanTarget() {
        return this.scanTarget;
    }

    public Document getResult() {
        return this.result;
    }
}
