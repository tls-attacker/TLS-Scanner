package de.rub.nds.tlsscanner.clientscanner.probe.downgrade;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseStatefulProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class DropConnection extends BaseStatefulProbe<DowngradeInternalState> {

    public DropConnection(IOrchestrator orchestrator) {
        super(orchestrator);
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return true;
    }

    @Override
    public ClientProbeResult getCouldNotExecuteResult(ClientReport report) {
        return null;
    }

    @Override
    protected DowngradeInternalState getDefaultState(DispatchInformation dispatchInformation) {
        return new DowngradeInternalState(getClass());
    }

    @Override
    protected DowngradeInternalState execute(State state, DispatchInformation dispatchInformation, DowngradeInternalState internalState) {
        // only analyze chlo
        internalState.putCHLO(dispatchInformation.chlo);
        executeState(state, dispatchInformation);
        return internalState;
    }
}
