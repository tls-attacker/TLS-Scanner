/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.core.probe.requirements.PropertyComparatorRequirement;
import de.rub.nds.tlsscanner.core.probe.requirements.PropertyRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/** Probe that checks if server enforces the order of named groups sent by the client */
public class NamedCurvesOrderProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private Collection<NamedGroup> supportedGroups;

    private TestResult enforced = TestResults.COULD_NOT_TEST;

    public NamedCurvesOrderProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.NAMED_GROUPS_ORDER, configSelector);
        register(TlsAnalyzedProperty.ENFORCES_NAMED_GROUP_ORDERING);
    }

    @Override
    public void executeTest() {
        List<NamedGroup> toTestList = new LinkedList<>(supportedGroups);
        NamedGroup firstSelectedNamedGroup = getSelectedNamedGroup(toTestList);
        Collections.reverse(toTestList);
        NamedGroup secondSelectedNamedGroup = getSelectedNamedGroup(toTestList);
        if (firstSelectedNamedGroup != secondSelectedNamedGroup || supportedGroups.size() == 1) {
            enforced = TestResults.TRUE;
        } else {
            enforced = TestResults.FALSE;
        }
    }

    public NamedGroup getSelectedNamedGroup(List<NamedGroup> toTestList) {
        Config tlsConfig = configSelector.getAnyWorkingBaseConfig();
        if (tlsConfig.getHighestProtocolVersion() != ProtocolVersion.TLS13) {
            List<CipherSuite> cipherSuites =
                    Arrays.stream(CipherSuite.values())
                            .filter(cipherSuite -> cipherSuite.name().contains("ECDH"))
                            .collect(Collectors.toList());
            tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        }
        tlsConfig.setEnforceSettings(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setDefaultClientNamedGroups(toTestList);
        configSelector.repairConfig(tlsConfig);
        State state = new State(tlsConfig);
        executeState(state);
        return state.getTlsContext().getSelectedGroup();
    }

    @Override
    protected Requirement getRequirements() {
        return new ProbeRequirement(TlsProbeType.NAMED_GROUPS, TlsProbeType.CIPHER_SUITE)
                .requires(new PropertyRequirement(TlsAnalyzedProperty.SUPPORTS_ECDHE))
                .requires(
                        new PropertyComparatorRequirement(
                                PropertyComparatorRequirement.GREATER,
                                TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS,
                                0));
    }

    @Override
    public void adjustConfig(ServerReport report) {
        supportedGroups = report.getSupportedNamedGroups();
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.ENFORCES_NAMED_GROUP_ORDERING, enforced);
    }
}
