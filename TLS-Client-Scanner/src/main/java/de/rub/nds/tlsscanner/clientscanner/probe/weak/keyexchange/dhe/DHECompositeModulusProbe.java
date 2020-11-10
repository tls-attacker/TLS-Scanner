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
import java.util.Random;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.ControlledClientDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.ControlledClientDispatcher.ControlledClientDispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHECompositeModulusProbe.CompositeType;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHECompositeModulusProbe.DHCompositeModulusProbeResult;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHEMinimumModulusLengthProbe.DHMinimumModulusLengthResult;
import de.rub.nds.tlsscanner.clientscanner.report.requirements.ProbeRequirements;

public class DHECompositeModulusProbe extends BaseDHEParametrizedProbe<CompositeType, DHCompositeModulusProbeResult> {
    private static Random random = new Random();

    enum CompositeType {
        EVEN,
        MOD3
    }

    public static Collection<DHECompositeModulusProbe> getDefaultProbes(Orchestrator orchestrator) {
        return Arrays.asList(
                new DHECompositeModulusProbe(orchestrator, CompositeType.EVEN),
                new DHECompositeModulusProbe(orchestrator, CompositeType.MOD3));
    }

    public DHECompositeModulusProbe(Orchestrator orchestrator, CompositeType compType) {
        super(orchestrator, false, false, true, compType);
    }

    @Override
    protected ProbeRequirements getRequirements() {
        return super.getRequirements()
                .needResultOfType(
                        DHEMinimumModulusLengthProbe.class,
                        DHMinimumModulusLengthResult.class);
    }

    protected BigInteger createModulus(int minBitLength) {
        BigInteger ret;
        switch (enumValue) {
            case EVEN:
                ret = BigInteger.probablePrime(minBitLength, random);
                ret = ret.add(BigInteger.ONE);
                return ret;
            case MOD3:
                ret = BigInteger.probablePrime(minBitLength, random);
                while (!ret.mod(BigInteger.valueOf(3)).equals(BigInteger.ZERO)) {
                    ret = ret.add(BigInteger.valueOf(2));
                }
                return ret;
        }
        throw new RuntimeException("Unknown type " + enumValue);
    }

    @Override
    public DHCompositeModulusProbeResult executeInternal(State state, DispatchInformation dispatchInformation)
            throws DispatchException {
        Config config = state.getConfig();
        int keylength = 2048;
        ControlledClientDispatchInformation ccInfo = dispatchInformation.getAdditionalInformation(
                ControlledClientDispatcher.class, ControlledClientDispatchInformation.class);
        if (ccInfo != null) {
            keylength = ccInfo.report.getResult(DHEMinimumModulusLengthProbe.class,
                    DHMinimumModulusLengthResult.class).lowestBitlengthAccepted;
        }
        prepareConfig(config);
        config.setDefaultServerDhModulus(createModulus(keylength));
        extendWorkflowTraceToApplication(state.getWorkflowTrace(), config);
        executeState(state, dispatchInformation);
        return new DHCompositeModulusProbeResult(state);
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class DHCompositeModulusProbeResult implements Serializable {
        public final boolean accepted;

        public DHCompositeModulusProbeResult(State state) {
            accepted = state.getWorkflowTrace().executedAsPlanned();
        }

    }

}
