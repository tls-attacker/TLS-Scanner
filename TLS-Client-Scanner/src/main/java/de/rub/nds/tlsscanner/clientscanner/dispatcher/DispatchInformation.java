package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;

public class DispatchInformation {
    public final ClientHelloMessage chlo;
    public final ClientScannerConfig csConfig;

    public DispatchInformation(ClientHelloMessage chlo, ClientScannerConfig csConfig) {
        this.chlo = chlo;
        this.csConfig = csConfig;
    }
}