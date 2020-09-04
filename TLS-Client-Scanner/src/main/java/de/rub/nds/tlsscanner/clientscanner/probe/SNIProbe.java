package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class SNIProbe extends BaseProbe {
    // TODO make this a post probe

    public SNIProbe(IOrchestrator orchestrator) {
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
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) {
        ServerNameIndicationExtensionMessage SNI = null;
        for (ExtensionMessage ext : dispatchInformation.chlo.getExtensions()) {
            if (ext instanceof ServerNameIndicationExtensionMessage) {
                SNI = (ServerNameIndicationExtensionMessage) ext;
                break;
            }
        }
        return new SNIProbeResult(SNI != null);
    }

    public static class SNIProbeResult extends ClientProbeResult {
        public final boolean supported;

        public SNIProbeResult(boolean supported) {
            this.supported = supported;
        }

        @Override
        public void merge(ClientReport report) {
            report.putResult(SNIProbe.class, this);
        }

    }

}