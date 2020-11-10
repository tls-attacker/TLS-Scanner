/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHEWeakPrivateKeyProbe.DHWeakPrivateKeyProbeResult;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHEWeakPrivateKeyProbe.PrivateKeyType;

public class DHEWeakPrivateKeyProbe extends BaseDHEParametrizedProbe<PrivateKeyType, DHWeakPrivateKeyProbeResult> {
    enum PrivateKeyType {
        ZERO,
        ONE
    }

    public static Collection<DHEWeakPrivateKeyProbe> getDefaultProbes(Orchestrator orchestrator) {
        return Arrays.asList(
                new DHEWeakPrivateKeyProbe(orchestrator, PrivateKeyType.ZERO),
                new DHEWeakPrivateKeyProbe(orchestrator, PrivateKeyType.ONE));
    }

    public DHEWeakPrivateKeyProbe(Orchestrator orchestrator, PrivateKeyType keyType) {
        // super(orchestrator, true, true, true, keyType);
        super(orchestrator, false, false, true, keyType);
    }

    @Override
    public DHWeakPrivateKeyProbeResult executeInternal(State state, DispatchInformation dispatchInformation)
            throws DispatchException {
        Config config = state.getConfig();
        prepareConfig(config);
        switch (enumValue) {
            case ZERO:
                config.setDefaultServerDhPrivateKey(BigInteger.ZERO);
                break;
            case ONE:
                config.setDefaultServerDhPrivateKey(BigInteger.ONE);
                break;
        }
        extendWorkflowTraceToApplication(state.getWorkflowTrace(), config);
        executeState(state, dispatchInformation);
        return new DHWeakPrivateKeyProbeResult(state);
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class DHWeakPrivateKeyProbeResult implements Serializable {
        public final boolean accepted;

        public DHWeakPrivateKeyProbeResult(State state) {
            accepted = state.getWorkflowTrace().executedAsPlanned();
        }

    }

}
