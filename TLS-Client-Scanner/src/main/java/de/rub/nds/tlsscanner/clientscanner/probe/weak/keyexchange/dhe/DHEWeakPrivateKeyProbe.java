package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.ParametrizedClientProbeResult;

public class DHEWeakPrivateKeyProbe extends BaseDHEProbe {

    public static Collection<DHEWeakPrivateKeyProbe> getDefaultProbes(IOrchestrator orchestrator) {
        return Arrays.asList(
                new DHEWeakPrivateKeyProbe(orchestrator, BigInteger.valueOf(0)),
                new DHEWeakPrivateKeyProbe(orchestrator, BigInteger.valueOf(1)));
    }

    private final BigInteger keyToTest;

    public DHEWeakPrivateKeyProbe(IOrchestrator orchestrator, BigInteger keyToTest) {
        super(orchestrator, true, true, true);
        this.keyToTest = keyToTest;
    }

    @Override
    public ParametrizedClientProbeResult<String, DHWeakPrivateKeyProbeResult> execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        Config config = state.getConfig();
        prepareConfig(config);
        config.setDefaultServerDhPrivateKey(keyToTest);
        extendWorkflowTraceToApplication(state.getWorkflowTrace(), config);
        executeState(state, dispatchInformation);
        return new ParametrizedClientProbeResult<>(getClass(),
                keyToTest.toString(), new DHWeakPrivateKeyProbeResult(state));
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class DHWeakPrivateKeyProbeResult implements Serializable {
        public final boolean accepted;

        public DHWeakPrivateKeyProbeResult(State state) {
            accepted = state.getWorkflowTrace().executedAsPlanned();
        }

    }

}
