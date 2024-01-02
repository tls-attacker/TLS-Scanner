/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.quic;

import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.QuicProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.TlsServerProbe;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class QuicServerProbe extends TlsServerProbe {

    protected static final Logger LOGGER = LogManager.getLogger();

    protected QuicServerProbe(
            ParallelExecutor parallelExecutor, QuicProbeType type, ConfigSelector configSelector) {
        super(parallelExecutor, type, configSelector);
    }
}
