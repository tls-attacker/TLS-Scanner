/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.passive;

import de.rub.nds.scanner.core.passive.StatExtractor;
import de.rub.nds.scanner.core.util.ComparableByteArray;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import java.util.Arrays;

public class SessionIdExtractor extends StatExtractor<State, ComparableByteArray> {

    public SessionIdExtractor() {
        super(TrackableValueType.SESSION_ID);
    }

    @Override
    public void extract(State state) {
        if (state.getTlsContext().getSelectedProtocolVersion() != ProtocolVersion.TLS13) {
            if (state.getTlsContext().getServerSessionId() != null) {
                if (!Arrays.equals(
                        state.getTlsContext().getClientSessionId(),
                        state.getTlsContext().getServerSessionId())) {
                    put(new ComparableByteArray(state.getTlsContext().getServerSessionId()));
                }
            }
        }
    }
}
