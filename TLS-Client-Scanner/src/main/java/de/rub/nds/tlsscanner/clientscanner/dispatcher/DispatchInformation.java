package de.rub.nds.tlsscanner.clientscanner.dispatcher;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.workflow.IStatePreparator;

public class DispatchInformation {
    public final ClientHelloMessage chlo;
    public final State chloState;
    public final IStatePreparator statePreparator;
    public final ClientScannerConfig csConfig;

    public DispatchInformation(ClientHelloMessage chlo, State chloState, IStatePreparator statePreparator,
            ClientScannerConfig csConfig) {
        this.chlo = chlo;
        this.chloState = chloState;
        this.statePreparator = statePreparator;
        this.csConfig = csConfig;
    }
}