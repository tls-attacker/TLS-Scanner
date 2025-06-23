/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.passive;

import de.rub.nds.modifiablevariable.util.ComparableByteArray;
import de.rub.nds.scanner.core.passive.StatExtractor;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import java.util.Arrays;

public class SessionIdExtractor extends StatExtractor<State, ComparableByteArray> {

    /** Constructs a new SessionIdExtractor for extracting session IDs from TLS states. */
    public SessionIdExtractor() {
        super(TrackableValueType.SESSION_ID);
    }

    /**
     * Extracts the server session ID from the given TLS state if it differs from the client session
     * ID. Session IDs are not extracted for TLS 1.3 connections.
     *
     * @param state the TLS state to extract the session ID from
     */
    @Override
    public void extract(State state) {
        if (state.getTlsContext().getSelectedProtocolVersion() != ProtocolVersion.TLS13
                && state.getTlsContext().getServerSessionId() != null
                && !Arrays.equals(
                        state.getTlsContext().getClientSessionId(),
                        state.getTlsContext().getServerSessionId())) {
            put(new ComparableByteArray(state.getTlsContext().getServerSessionId()));
        }
    }
}
