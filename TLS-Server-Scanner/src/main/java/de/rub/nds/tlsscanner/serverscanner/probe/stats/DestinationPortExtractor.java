/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.stats;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.udp.UdpTransportHandler;

public class DestinationPortExtractor extends StatExtractor<Integer> {

    public DestinationPortExtractor() {
        super(TrackableValueType.DESTINATION_PORT);
    }

    @Override
    public void extract(State state) {
        if (state.getTlsContext().getTransportHandler() instanceof UdpTransportHandler) {
            int port = ((UdpTransportHandler) state.getTlsContext().getTransportHandler()).getDstPort();
            if (port != -1) {
                put(port);
            }
        }
    }

}
