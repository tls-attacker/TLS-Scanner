/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.NamedGroupOrderResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
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
public class NamedCurvesOrderProbe extends TlsProbe {

    private Collection<NamedGroup> supportedGroups;

    public NamedCurvesOrderProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.NAMED_GROUPS_ORDER, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        List<NamedGroup> toTestList = new LinkedList<>(supportedGroups);
        NamedGroup firstSelectedNamedGroup = getSelectedNamedGroup(toTestList);
        Collections.reverse(toTestList);
        NamedGroup secondSelectedNamedGroup = getSelectedNamedGroup(toTestList);

        return new NamedGroupOrderResult(
            firstSelectedNamedGroup != secondSelectedNamedGroup || supportedGroups.size() == 1 ? TestResult.TRUE
                : TestResult.FALSE);
    }

    public NamedGroup getSelectedNamedGroup(List<NamedGroup> toTestList) {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setEarlyStop(true);
        List<CipherSuite> cipherSuites = Arrays.stream(CipherSuite.values())
            .filter(cipherSuite -> cipherSuite.name().contains("ECDH")).collect(Collectors.toList());
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(true);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setDefaultClientNamedGroups(toTestList);
        State state = new State(tlsConfig);
        executeState(state);
        return state.getTlsContext().getSelectedGroup();
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.isProbeAlreadyExecuted(ProbeType.NAMED_GROUPS) && !report.getSupportedNamedGroups().isEmpty()
            && report.isProbeAlreadyExecuted(ProbeType.CIPHER_SUITE)
            && report.getCipherSuites().stream().anyMatch(cipherSuite -> cipherSuite.name().contains("ECDH"));
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new NamedGroupOrderResult(TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportedGroups = report.getSupportedNamedGroups();
    }
}
