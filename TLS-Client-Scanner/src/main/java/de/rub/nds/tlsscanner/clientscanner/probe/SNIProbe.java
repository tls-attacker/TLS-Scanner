package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class SNIProbe extends BaseProbe {
    // TODO make this a post probe

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return true;
    }

    @Override
    public ClientProbeResult getCouldNotExecuteResult() {
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
        public String getProbeName() {
            return "SNI Probe";
        }

        @Override
        public void merge(ClientReport report) {
            report.putResult(SNIProbe.class, this);
        }

    }

}