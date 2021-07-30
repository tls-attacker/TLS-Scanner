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
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIDispatcher.SNIDispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SNIUidDispatcher implements Dispatcher {
    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        SNIDispatchInformation info =
            dispatchInformation.getAdditionalInformation(SNIDispatcher.class, SNIDispatchInformation.class);
        if (!info.handledHostname.equalsIgnoreCase("uid")) {
            throw new DispatchException(
                "SNI UID dispatcher expects previous hostname to be \"uid\", got: " + info.handledHostname);
        }
        int splitIndex = info.remainingHostname.lastIndexOf('.');
        String uid = info.remainingHostname.substring(splitIndex + 1);
        String remaining = info.remainingHostname.substring(0, splitIndex);
        LOGGER.debug("Found uid \"{}\" - remaining \"{}\"", uid, remaining);
        dispatchInformation.additionalInformation.put(SNIUidDispatcher.class, new UidInformation(uid));
        return info.dispatcher.dispatch(state, dispatchInformation, remaining);
    }

    public static class UidInformation {
        public final String uid;

        public UidInformation(String uid) {
            this.uid = uid;
        }
    }
}
