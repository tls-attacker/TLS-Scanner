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
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.scanner.core.report.ScanReport;
import java.util.concurrent.Callable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ScannerProbe<Report extends ScanReport, Result extends ProbeResult<Report>>
    implements Callable<ProbeResult> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProbeType type;

    private StatsWriter writer;

    public ScannerProbe(ProbeType type) {
        this.type = type;
    }

    public ProbeType getType() {
        return type;
    }

    public String getProbeName() {
        return getType().getName();
    }

    public abstract Result executeTest();

    public abstract boolean canBeExecuted(Report report);

    public abstract Result getCouldNotExecuteResult();

    public abstract void adjustConfig(Report report);

    @Override
    public Result call() {
        LOGGER.debug("Executing: {}", getProbeName());
        long startTime = System.currentTimeMillis();
        Result result = executeTest();
        long stopTime = System.currentTimeMillis();
        if (result != null) {
            result.setStartTime(startTime);
            result.setStopTime(stopTime);
        } else {
            LOGGER.warn("{} - is null result", getProbeName());
        }

        LOGGER.debug("Finished {} -  Took {}s", getProbeName(), (stopTime - startTime) / 1000);
        return result;
    }

    public void executeAndMerge(Report report) {
        Result result = this.call();
        result.merge(report);
    }

    public StatsWriter getWriter() {
        return writer;
    }

    public void setWriter(StatsWriter writer) {
        this.writer = writer;
    }
}
