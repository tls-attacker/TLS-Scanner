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
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ClientUdpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ServerUdpTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.UdpTransportHandler;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;

public class DestinationPortExtractor extends StatExtractor<State, Integer> {

    public DestinationPortExtractor() {
        super(TrackableValueType.DESTINATION_PORT);
    }

    @Override
    public void extract(State state) {
        TransportHandler handler = state.getTlsContext().getTransportHandler();
        if (handler instanceof ClientUdpTransportHandler
                || handler instanceof ServerUdpTransportHandler) {
            int port = ((UdpTransportHandler) handler).getDstPort();
            if (port != -1) {
                put(port);
            }
        }
    }
}
