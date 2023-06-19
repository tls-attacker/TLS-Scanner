/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.probe;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.passive.StatsWriter;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import java.util.concurrent.Callable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ScannerProbe<R extends ScanReport<R>, P extends ScannerProbe<R, P>>
        implements Callable<P> {

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

    public abstract void adjustConfig(R report);

    @Override
    public P call() {
        LOGGER.debug("Executing: {}", getProbeName());
        this.startTime = System.currentTimeMillis();
        executeTest();
        this.stopTime = System.currentTimeMillis();

        LOGGER.debug("Finished {} -  Took {}s", getProbeName(), (stopTime - startTime) / 1000);
        return (P) this;
    }

    /**
     * @return the requirement object of the probe. Override for respective probes.
     */
    public abstract Requirement<R> getRequirements();

    public abstract void merge(R report);

    public final boolean canBeExecuted(R report) {
        return getRequirements().evaluate(report);
    }

    public StatsWriter getWriter() {
        return writer;
    }

    public void setWriter(StatsWriter writer) {
        this.writer = writer;
    }
}
