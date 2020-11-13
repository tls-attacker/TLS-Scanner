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
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHESmallSubgroupProbe.DHESmallSubgroupResult;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHESmallSubgroupProbe.SmallSubgroupType;

public class DHESmallSubgroupProbe extends BaseDHEParametrizedProbe<SmallSubgroupType, DHESmallSubgroupResult> {
    enum SmallSubgroupType {
        ONE,
        MINUS_ONE
    }

    public static Collection<DHESmallSubgroupProbe> getDefaultProbes(Orchestrator orchestrator) {
        return Arrays.asList(
                new DHESmallSubgroupProbe(orchestrator, SmallSubgroupType.ONE),
                new DHESmallSubgroupProbe(orchestrator, SmallSubgroupType.MINUS_ONE));
    }

    public DHESmallSubgroupProbe(Orchestrator orchestrator, SmallSubgroupType groupType) {
        super(orchestrator, false, false, true, groupType);
    }

    @Override
    public DHESmallSubgroupResult executeInternal(State state, DispatchInformation dispatchInformation)
            throws DispatchException {
        Config config = state.getConfig();
        prepareConfig(config);
        switch (enumValue) {
            case ONE:
                config.setDefaultServerDhGenerator(BigInteger.ONE);
                break;
            case MINUS_ONE:
                config.setDefaultServerDhGenerator(config.getDefaultClientDhModulus().subtract(BigInteger.ONE));
                break;
            default:
                throw new DispatchException("Failed to generate generator; unknown type " + enumValue);
        }
        extendWorkflowTraceToApplication(state.getWorkflowTrace(), config, false);
        executeState(state, dispatchInformation);
        return new DHESmallSubgroupResult(state);
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class DHESmallSubgroupResult implements Serializable {
        public final boolean accepted;

        public DHESmallSubgroupResult(State state) {
            accepted = state.getWorkflowTrace().executedAsPlanned();
        }

    }

}
