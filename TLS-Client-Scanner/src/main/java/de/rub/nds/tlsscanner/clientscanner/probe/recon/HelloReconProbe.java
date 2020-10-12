package de.rub.nds.tlsscanner.clientscanner.probe.recon;

import javax.xml.bind.annotation.XmlTransient;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.requirements.ProbeRequirements;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class HelloReconProbe extends BaseProbe {

    public HelloReconProbe(IOrchestrator orchestrator) {
        super(orchestrator);
    }

    @Override
    protected ProbeRequirements getRequirements() {
        return null;
    }

    @Override
    public HelloReconResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        return new HelloReconResult(state, dispatchInformation.chlo);
    }

    @XmlTransient()
    public static class HelloReconResult extends ClientProbeResult {
        public final transient State state;
        public final ClientHelloMessage chlo;

        public HelloReconResult(State state, ClientHelloMessage chlo) {
            this.state = state;
            this.chlo = chlo;
        }

        @Override
        public void merge(ClientReport report) {
            report.putResult(HelloReconProbe.class, this);
        }
    }
}
