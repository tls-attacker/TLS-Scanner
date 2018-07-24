/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import java.util.concurrent.Callable;
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

    public TlsProbe(ProbeType type, ScannerConfig scannerConfig, int danger) {
        this.scannerConfig = scannerConfig;
        this.type = type;
        this.danger = danger;
    }

    public int getDanger() {
        return danger;
    }

    public ScannerConfig getScannerConfig() {
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
        result.setStarttime(startTime);
        result.setStoptime(stopTime);
        LOGGER.info("Finished " + getProbeName() + " -  Took " + (stopTime - startTime) / 1000 + "s");
        return result;
    }
    
    public abstract ProbeResult executeTest();

    public abstract boolean shouldBeExecuted(SiteReport report);

    public abstract void adjustConfig(SiteReport report);

    public abstract ProbeResult getNotExecutedResult();
}
