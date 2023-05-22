/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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

import java.util.concurrent.Callable;

public abstract class ScannerProbe<Report extends ScanReport> implements Callable {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProbeType type;

    private StatsWriter writer;

    private long startTime;
    private long stopTime;

    /**
     * @return the startTime
     */
    public long getStartTime() {
        return startTime;
    }

    /**
     * @return the stopTime
     */
    public long getStopTime() {
        return stopTime;
    }

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
    public ScannerProbe<?> call() {
        LOGGER.debug("Executing: {}", getProbeName());
        this.startTime = System.currentTimeMillis();
        executeTest();
        this.stopTime = System.currentTimeMillis();

        LOGGER.debug("Finished {} -  Took {}s", getProbeName(), (stopTime - startTime) / 1000);
        return this;
    }

    /**
     * @return the requirement object of the probe. Override for respective probes.
     */
    public abstract Requirement getRequirements();

    public abstract void merge(Report report);

    public final boolean canBeExecuted(Report report) {
        return getRequirements().evaluate(report);
    }

    public StatsWriter getWriter() {
        return writer;
    }

    public void setWriter(StatsWriter writer) {
        this.writer = writer;
    }
}
