/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.ProbeResult;
import java.util.concurrent.Callable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class TLSProbe implements Callable<ProbeResult> {

    protected static final Logger LOGGER = LogManager.getLogger(TLSProbe.class.getName());

    protected final ScannerConfig scannerConfig;
    protected final ProbeType type;

    public TLSProbe(ProbeType type, ScannerConfig config) {
        this.type = type;
        this.scannerConfig = config;
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
    public abstract ProbeResult call();
}
