/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Probe that checks if server enforces the order of named groups sent by the client
 *
 */
public class NamedCurvesOrderProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private Collection<NamedGroup> supportedGroups;

    private TestResult enforced;

    public NamedCurvesOrderProbe(ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.NAMED_GROUPS_ORDER, scannerConfig);
        super.register(TlsAnalyzedProperty.ENFORCES_NAMED_GROUP_ORDERING);
    }

    @Override
    public void executeTest() {
        List<NamedGroup> toTestList = new LinkedList<>(supportedGroups);
        NamedGroup firstSelectedNamedGroup = getSelectedNamedGroup(toTestList);
        Collections.reverse(toTestList);
        NamedGroup secondSelectedNamedGroup = getSelectedNamedGroup(toTestList);
        enforced = firstSelectedNamedGroup != secondSelectedNamedGroup || supportedGroups.size() == 1 ? TestResults.TRUE
            : TestResults.FALSE;
    }

    public NamedGroup getSelectedNamedGroup(List<NamedGroup> toTestList) {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setEarlyStop(true);
        List<CipherSuite> cipherSuites = Arrays.stream(CipherSuite.values())
            .filter(cipherSuite -> cipherSuite.name().contains("ECDH")).collect(Collectors.toList());
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setEnforceSettings(true);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setDefaultClientNamedGroups(toTestList);
        State state = new State(tlsConfig);
        executeState(state);
        return state.getTlsContext().getSelectedGroup();
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        return new ProbeRequirement(report).requireProbeTypes(TlsProbeType.NAMED_GROUPS, TlsProbeType.CIPHER_SUITE)
            .requireAnalyzedProperties(TlsAnalyzedProperty.SUPPORTS_ECDHE);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void adjustConfig(ServerReport report) {
        supportedGroups =
            ((ListResult<NamedGroup>) report.getResultMap().get(TlsAnalyzedProperty.LIST_SUPPORTED_NAMEDGROUPS.name()))
                .getList();
    }

    @Override
    protected void mergeData(ServerReport report) {
        super.put(TlsAnalyzedProperty.ENFORCES_NAMED_GROUP_ORDERING, enforced);
    }
}
