package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import java.math.BigInteger;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class DHWeakPrivateKeyProbe extends BaseDHEProbe {

    public DHWeakPrivateKeyProbe(IOrchestrator orchestrator) {
        super(orchestrator);
    }

    @Override
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        Config config = state.getConfig();
        config.setDefaultServerDhPrivateKey(BigInteger.valueOf(1));
        extendWorkflowTrace(state.getWorkflowTrace(), WorkflowTraceType.HANDSHAKE, config);
        executeState(state);
        return new DHWeakPrivateKeyProbeResult(state);
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class DHWeakPrivateKeyProbeResult extends ClientProbeResult {
        public final boolean vulnerable;

        public DHWeakPrivateKeyProbeResult(State state) {
            vulnerable = state.getWorkflowTrace().executedAsPlanned();
        }

        @Override
        public void merge(ClientReport report) {
            report.putResult(DHWeakPrivateKeyProbe.class, this);
        }

    }

}
