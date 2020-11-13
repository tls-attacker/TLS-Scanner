/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public interface Dispatcher {
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException;
}