/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.probe.stats.StatsWriter;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class TlsProbe implements Callable<ProbeResult> {

    protected static final Logger LOGGER = LogManager.getLogger(TlsProbe.class.getName());

    protected final ScannerConfig scannerConfig;
    protected final ProbeType type;

    private final int danger;

    private final ParallelExecutor parallelExecutor;

    private final StatsWriter writer;

    private AtomicBoolean readyForExecution = new AtomicBoolean(false);

    public TlsProbe(ParallelExecutor parallelExecutor, ProbeType type, ScannerConfig scannerConfig, int danger) {
        this.scannerConfig = scannerConfig;
        this.type = type;
        this.danger = danger;
        this.parallelExecutor = parallelExecutor;
        this.writer = new StatsWriter();
    }

    public int getDanger() {
        return danger;
    }

    public final ScannerConfig getScannerConfig() {
        return scannerConfig;
    }

    public String getProbeName() {
        return type.name();
    }

    public ProbeType getType() {
        return type;
    }

    @Override
    public ProbeResult call() {
        LOGGER.info("Executing:" + getProbeName());
        long startTime = System.currentTimeMillis();
        ProbeResult result = executeTest();
        long stopTime = System.currentTimeMillis();
        if (result != null) {
            result.setStarttime(startTime);
            result.setStoptime(stopTime);
        } else {
            LOGGER.warn("" + getProbeName() + " - is null result");
        }

        LOGGER.info(
                "Finished " + getProbeName() + " -  Took " + (stopTime - startTime) / 1000 + "s");
        return result;
    }

    public final void executeState(State... states) {
        this.executeState(new ArrayList<State>(Arrays.asList(states)));

    }

    public final void executeState(List<State> states) {
        parallelExecutor.bulkExecuteStateTasks(states);
        for (State state : states) {
            writer.extract(state);
        }

    }

    public abstract ProbeResult executeTest();

    public void executeAndMerge(SiteReport report) {
        ProbeResult result = this.call();
        result.merge(report);
    }

    public abstract boolean canBeExecuted(SiteReport report);
    
    public abstract ProbeResult getCouldNotExecuteResult();

    public abstract void adjustConfig(SiteReport report);

    public ParallelExecutor getParallelExecutor() {
        return parallelExecutor;
    }

    public StatsWriter getWriter() {
        return writer;
    }

    public AtomicBoolean getReadyForExecution() {
        return readyForExecution;
    }
}
