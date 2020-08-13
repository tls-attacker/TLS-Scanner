package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;

public class DispatchInformation {
    public final ClientHelloMessage chlo;

    public DispatchInformation(ClientHelloMessage chlo) {
        this.chlo = chlo;
    }
}