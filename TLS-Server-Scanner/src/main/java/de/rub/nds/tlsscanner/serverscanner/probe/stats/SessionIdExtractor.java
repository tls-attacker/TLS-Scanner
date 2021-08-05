/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.stats;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import java.util.Arrays;

public class SessionIdExtractor extends StatExtractor<ComparableByteArray> {

    public SessionIdExtractor() {
        super(TrackableValueType.SESSION_ID);
    }

    @Override
    public void extract(State state) {
        if (state.getTlsContext().getSelectedProtocolVersion() != ProtocolVersion.TLS13) {
            if (state.getTlsContext().getServerSessionId() != null) {
                if (!Arrays.equals(state.getTlsContext().getClientSessionId(),
                    state.getTlsContext().getServerSessionId())) {
                    put(new ComparableByteArray(state.getTlsContext().getServerSessionId()));
                }
            }
        }
    }

}
