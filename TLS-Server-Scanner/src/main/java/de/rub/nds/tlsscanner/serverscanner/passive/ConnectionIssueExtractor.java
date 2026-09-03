package de.rub.nds.tlsscanner.serverscanner.passive;

import de.rub.nds.scanner.core.passive.StatExtractor;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;

public class ConnectionIssueExtractor extends StatExtractor<State, Boolean> {

    public ConnectionIssueExtractor() {
        super(TrackableValueType.CONNECTION_ISSUE);
    }

    @Override
    public void extract(State state) {
        var transportHandler = state.getContext().getTransportHandler();
        if(!transportHandler.isInitialized()){
            put(false);
        }
    }
}
