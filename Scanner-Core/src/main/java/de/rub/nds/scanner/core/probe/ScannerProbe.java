/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.probe;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.passive.StatsWriter;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ScannerProbe<Report extends ScanReport>
    implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final ProbeType type;

    private StatsWriter writer;
    
    protected long startTime;
    protected long stopTime;

    public ScannerProbe(ProbeType type) {
        this.type = type;
    }

    public ProbeType getType() {
        return type;
    }

    public String getProbeName() {
        return getType().getName();
    }

    public abstract void executeTest();

    public abstract void adjustConfig(Report report);

    @Override
    public void run() {
        LOGGER.debug("Executing: {}", getProbeName());
        this.startTime = System.currentTimeMillis();
        executeTest();
        this.stopTime = System.currentTimeMillis();

        LOGGER.debug("Finished {} -  Took {}s", getProbeName(), (stopTime - startTime) / 1000);
    }

    public void executeAndMerge(Report report) {
        this.run();
        merge(report);
    }

    /**
     * Override for individual requirements.
     * 
     * @param  report
     * @return        ProbeRequirement object without requirements (default)
     */
    protected abstract Requirement getRequirements(Report report);

    public abstract void merge(Report report);
    
    public boolean canBeExecuted(Report report) {
        return getRequirements(report).evaluateRequirements();
    }

    public abstract ScannerProbe<?> getCouldNotExecuteResult();

    public StatsWriter getWriter() {
        return writer;
    }

    public void setWriter(StatsWriter writer) {
        this.writer = writer;
    }
}
