/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.dispatcher.sni;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.Dispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIDispatcher.NoSNIExtensionException;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIDispatcher.NoSNINameException;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIDispatcher.SNIDispatchException;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIDispatcher.UnknownSNINameException;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SNIFallingBackDispatcher implements Dispatcher {
    private static final Logger LOGGER = LogManager.getLogger();
    public final Dispatcher next;
    public final Dispatcher fallbackNoSNI;
    public final Dispatcher fallbackNoSNIName;
    public final Dispatcher fallbackUnknownSNIName;
    public final Dispatcher fallbackOtherSNIException;

    public SNIFallingBackDispatcher(Dispatcher next, Dispatcher fallback) {
        this(next, fallback, fallback, fallback, fallback);
    }

    public SNIFallingBackDispatcher(Dispatcher next, Dispatcher fallbackNoSNI, Dispatcher fallbackNoSNIName,
        Dispatcher fallbackUnknownSNIName, Dispatcher fallbackOtherSNIException) {
        this.next = next;
        this.fallbackNoSNI = fallbackNoSNI;
        this.fallbackNoSNIName = fallbackNoSNIName;
        this.fallbackUnknownSNIName = fallbackUnknownSNIName;
        this.fallbackOtherSNIException = fallbackOtherSNIException;
    }

    private ClientProbeResult fallback(SNIDispatchException ex, State state, DispatchInformation dispatchInformation)
        throws DispatchException {
        Dispatcher fallback = fallbackOtherSNIException;
        LOGGER.debug("Falling back, got Exception {}", ex.getClass().getSimpleName());
        if (ex instanceof NoSNIExtensionException) {
            fallback = fallbackNoSNI;
        } else if (ex instanceof NoSNINameException) {
            fallback = fallbackNoSNIName;
        } else if (ex instanceof UnknownSNINameException) {
            fallback = fallbackUnknownSNIName;
        }
        if (fallback == null) {
            throw ex;
        }
        return fallback.execute(state, dispatchInformation);
    }

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        try {
            return next.execute(state, dispatchInformation);
        } catch (SNIDispatchException e) {
            return fallback(e, state, dispatchInformation);
        }
    }

}
