/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.data;

import de.rub.nds.crawler.core.BulkScanWorker;
import de.rub.nds.crawler.data.ScanConfig;
import de.rub.nds.crawler.persistence.IPersistenceProvider;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.probe.ProbeType;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlscrawler.core.TlsScanWorker;
import java.util.List;

public class TlsScanConfig extends ScanConfig {

    /** Default minimum interval between partial-result writes to MongoDB, in milliseconds. */
    public static final long DEFAULT_PARTIAL_RESULT_THROTTLE_MS = 5000;

    private StarttlsType starttlsType;

    /**
     * Minimum interval in milliseconds between partial-result writes to MongoDB for a single scan
     * target. A value {@code <= 0} disables throttling, causing every progress update to be
     * written. Throttling is applied per scan target inside the worker (see {@link
     * de.rub.nds.tlscrawler.core.TlsScanWorker}).
     */
    private long partialResultThrottleMs = DEFAULT_PARTIAL_RESULT_THROTTLE_MS;

    /**
     * Whether to emit partial (in-progress) results during a scan. Defaults to {@code false}: the
     * primary bulk-crawl use case does not need live progress, and enabling it adds per-step report
     * serialization and MongoDB write load. Consumers that want live updates (e.g. the web UI) must
     * opt in by setting this to {@code true}.
     */
    private boolean partialResultsEnabled = false;

    public TlsScanConfig(
            ScannerDetail scannerDetail,
            int reexecutions,
            int timeout,
            int parallelProbes,
            StarttlsType starttlsType,
            List<ProbeType> excludedProbes) {
        super(scannerDetail, reexecutions, timeout, parallelProbes, excludedProbes);
        this.starttlsType = starttlsType;
    }

    @Override
    public BulkScanWorker<TlsScanConfig> createWorker(
            String bulkScanID,
            int parallelConnectionThreads,
            int parallelScanThreads,
            IPersistenceProvider persistenceProvider) {
        return new TlsScanWorker(
                bulkScanID,
                parallelConnectionThreads,
                this,
                parallelScanThreads,
                persistenceProvider);
    }

    public StarttlsType getStarttlsType() {
        return starttlsType;
    }

    public void setStarttlsType(StarttlsType starttlsType) {
        if (starttlsType == null) {
            throw new IllegalArgumentException("starttlsType cannot be null");
        }
        this.starttlsType = starttlsType;
    }

    public long getPartialResultThrottleMs() {
        return partialResultThrottleMs;
    }

    public void setPartialResultThrottleMs(long partialResultThrottleMs) {
        this.partialResultThrottleMs = partialResultThrottleMs;
    }

    public boolean isPartialResultsEnabled() {
        return partialResultsEnabled;
    }

    public void setPartialResultsEnabled(boolean partialResultsEnabled) {
        this.partialResultsEnabled = partialResultsEnabled;
    }
}
