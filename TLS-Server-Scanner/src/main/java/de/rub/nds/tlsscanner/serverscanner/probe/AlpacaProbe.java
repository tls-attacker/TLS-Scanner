/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class AlpacaProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private boolean alpnSupported;
    private TestResult strictSni;
    private TestResult strictAlpn;

    public AlpacaProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CROSS_PROTOCOL_ALPACA, configSelector);
        register(TlsAnalyzedProperty.STRICT_SNI, TlsAnalyzedProperty.STRICT_ALPN, TlsAnalyzedProperty.ALPACA_MITIGATED);
    }

    @Override
    public void executeTest() {
        strictSni = isSupportingStrictSni();
        if (!alpnSupported) {
            strictAlpn = TestResults.FALSE;
        } else {
            strictAlpn = isSupportingStrictAlpn();
        }
    }

    private TestResult isSupportingStrictSni() {
        Config tlsConfig = configSelector.getAnyWorkingBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.getDefaultClientConnection().setHostname("notarealtls-attackerhost.com");
        tlsConfig.setAddAlpnExtension(false);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResults.FALSE;
        } else {
            return TestResults.TRUE;
        }
    }

    private TestResult isSupportingStrictAlpn() {
        Config tlsConfig = configSelector.getAnyWorkingBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddAlpnExtension(true);
        tlsConfig.setDefaultProposedAlpnProtocols("NOT an ALPN protocol");
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(
                HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResults.FALSE;
        } else {
            return TestResults.TRUE;
        }
    }

    @Override
    protected Requirement getRequirements() {
        return new ProbeRequirement(TlsProbeType.EXTENSIONS);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        alpnSupported = report.getSupportedExtensions().contains(ExtensionType.ALPN);
    }

    @Override
    protected void mergeData(ServerReport report) {
        if ((strictSni == TestResults.TRUE || strictSni == TestResults.FALSE)
            && (strictAlpn == TestResults.TRUE || strictAlpn == TestResults.FALSE)) {
            TestResult alpacaMitigated;
            if (strictAlpn == TestResults.TRUE && strictSni == TestResults.TRUE) {
                alpacaMitigated = TestResults.TRUE;
            } else if (strictAlpn == TestResults.TRUE || strictSni == TestResults.TRUE) {
                alpacaMitigated = TestResults.PARTIALLY;
            } else {
                alpacaMitigated = TestResults.FALSE;
            }

            put(TlsAnalyzedProperty.STRICT_SNI, strictSni);
            put(TlsAnalyzedProperty.STRICT_ALPN, strictAlpn);
            put(TlsAnalyzedProperty.ALPACA_MITIGATED, alpacaMitigated);
        } else {
            put(TlsAnalyzedProperty.STRICT_SNI, strictSni);
            put(TlsAnalyzedProperty.STRICT_ALPN, strictAlpn);
            put(TlsAnalyzedProperty.ALPACA_MITIGATED, TestResults.UNCERTAIN);
        }
    }
}
