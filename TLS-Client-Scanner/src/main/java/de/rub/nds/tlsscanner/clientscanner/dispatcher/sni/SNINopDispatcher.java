/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.dispatcher.sni;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.Dispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIDispatcher.SNIDispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class SNINopDispatcher implements Dispatcher {
    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        SNIDispatchInformation info = dispatchInformation.getAdditionalInformation(SNIDispatcher.class,
                SNIDispatchInformation.class);
        return info.dispatcher.dispatch(state, dispatchInformation, info.remainingHostname);
    }

}
