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
import de.rub.nds.tlsscanner.clientscanner.client.IOrchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.DispatchInformation;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;
import de.rub.nds.tlsscanner.clientscanner.report.result.ParametrizedClientProbeResult;

public class DHESmallSubgroupProbe extends BaseDHEProbe {
    private static Random random = new Random();

    enum SmallSubgroupType {
        ONE,
        MINUS_ONE
    }

    public static Collection<DHESmallSubgroupProbe> getDefaultProbes(IOrchestrator orchestrator) {
        return Arrays.asList(
                new DHESmallSubgroupProbe(orchestrator, SmallSubgroupType.ONE),
                new DHESmallSubgroupProbe(orchestrator, SmallSubgroupType.MINUS_ONE));
    }

    private final SmallSubgroupType groupType;

    public DHESmallSubgroupProbe(IOrchestrator orchestrator, SmallSubgroupType groupType) {
        super(orchestrator, false, false, true);
        this.groupType = groupType;
    }

    @Override
    protected String getHostnamePrefix() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.groupType.name());
        sb.append('.');
        sb.append(super.getHostnamePrefix());
        return sb.toString();
    }

    @Override
    public ParametrizedClientProbeResult<SmallSubgroupType, DHESmallSubgroupResult> execute(State state, DispatchInformation dispatchInformation) throws DispatchException {
        Config config = state.getConfig();
        prepareConfig(config);
        switch (groupType) {
            case ONE:
                config.setDefaultServerDhGenerator(BigInteger.ONE);
                break;
            case MINUS_ONE:
                config.setDefaultServerDhGenerator(config.getDefaultClientDhModulus().subtract(BigInteger.ONE));
                break;
            default:
                throw new DispatchException("Failed to generate generator; unknown type " + groupType);
        }
        extendWorkflowTraceToApplication(state.getWorkflowTrace(), config);
        executeState(state, dispatchInformation);
        return new ParametrizedClientProbeResult<>(getClass(),
                groupType, new DHESmallSubgroupResult(state));
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class DHESmallSubgroupResult implements Serializable {
        public final boolean accepted;

        public DHESmallSubgroupResult(State state) {
            accepted = state.getWorkflowTrace().executedAsPlanned();
        }

    }

}
