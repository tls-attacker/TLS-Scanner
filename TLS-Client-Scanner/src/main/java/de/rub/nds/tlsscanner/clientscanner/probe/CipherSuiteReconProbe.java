package de.rub.nds.tlsscanner.clientscanner.probe;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class CipherSuiteReconProbe extends BaseProbe {

    public CipherSuiteReconProbe(IOrchestrator orchestrator) {
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
    public ClientProbeResult execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        return new CipherSuiteReconResult(state);
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class CipherSuiteReconResult extends ClientProbeResult {
        private final List<CipherSuite> supportedSuites;

        public CipherSuiteReconResult(State state) {
            supportedSuites = new ArrayList<>(state.getTlsContext().getClientSupportedCiphersuites());
        }

        public List<CipherSuite> getSupportedSuites() {
            return Collections.unmodifiableList(supportedSuites);
        }

        public boolean supportsKeyExchangeDHE() {
            for (CipherSuite cs : supportedSuites) {
                if (cs.isTLS13() || (cs.usesDH() && cs.isEphemeral())) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public void merge(ClientReport report) {
            report.putResult(CipherSuiteReconProbe.class, this);
        }

    }

}
