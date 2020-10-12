package de.rub.nds.tlsscanner.clientscanner.dispatcher.sni;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.sni.SNIDispatcher.SNIDispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class SNINopDispatcher implements IDispatcher {
    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        SNIDispatchInformation info = dispatchInformation.getAdditionalInformation(SNIDispatcher.class, SNIDispatchInformation.class);
        return info.dispatcher.dispatch(state, dispatchInformation, info.remainingHostname);
    }

}
