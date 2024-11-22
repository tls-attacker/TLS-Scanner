/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import static java.nio.charset.StandardCharsets.US_ASCII;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.SniType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;
import java.util.List;

public class AlpacaProbe extends TlsServerProbe {

    private boolean alpnSupported;
    private TestResult strictSni = TestResults.COULD_NOT_TEST;
    private TestResult strictAlpn = TestResults.COULD_NOT_TEST;

    public AlpacaProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CROSS_PROTOCOL_ALPACA, configSelector);
        register(
                TlsAnalyzedProperty.STRICT_SNI,
                TlsAnalyzedProperty.STRICT_ALPN,
                TlsAnalyzedProperty.ALPACA_MITIGATED);
    }

    @Override
    protected void executeTest() {
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
        tlsConfig.setDefaultSniHostnames(
                new LinkedList<>(
                        List.of(
                                new ServerNamePair(
                                        SniType.HOST_NAME.getValue(),
                                        "notarealtls-attackerhost.com".getBytes(US_ASCII)))));
        tlsConfig.setAddAlpnExtension(false);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
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
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)) {
            return TestResults.FALSE;
        } else {
            return TestResults.TRUE;
        }
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<>(TlsProbeType.EXTENSIONS);
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
