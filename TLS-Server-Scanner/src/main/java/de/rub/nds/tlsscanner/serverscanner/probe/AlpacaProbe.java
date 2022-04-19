/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class AlpacaProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private boolean alpnSupported;
    private TestResult strictSni;
    private TestResult strictAlpn;

    public AlpacaProbe(ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CROSS_PROTOCOL_ALPACA, scannerConfig);
        super.register(TlsAnalyzedProperty.STRICT_SNI);
        super.register(TlsAnalyzedProperty.STRICT_ALPN);
        super.register(TlsAnalyzedProperty.ALPACA_MITIGATED);
    }

    @Override
    public void executeTest() {
        this.strictSni = isSupportingStrictSni();
        if (!this.alpnSupported)
            this.strictAlpn = TestResults.FALSE;
        else
            this.strictAlpn = isSupportingStrictAlpn();
    }

    private Config getBaseConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddAlpnExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setStopActionsAfterIOException(true);
        List<NamedGroup> nameGroups = Arrays.asList(NamedGroup.values());
        tlsConfig.setDefaultClientNamedGroups(nameGroups);
        return tlsConfig;
    }

    private TestResult isSupportingStrictSni() {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.getDefaultClientConnection().setHostname("notarealtls-attackerhost.com");
        tlsConfig.setAddAlpnExtension(false);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResults.FALSE;
        } else {
            return TestResults.TRUE;
        }
    }

    private TestResult isSupportingStrictAlpn() {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddAlpnExtension(true);
        tlsConfig.setDefaultProposedAlpnProtocols("NOT an ALPN protocol");

        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResults.FALSE;
        } else {
            return TestResults.TRUE;
        }
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        return new ProbeRequirement(report).requireProbeTypes(TlsProbeType.EXTENSIONS);
    }

    @Override
    public AlpacaProbe getCouldNotExecuteResult() {
        this.strictSni = this.strictAlpn = TestResults.COULD_NOT_TEST;
        return this;
    }

    @Override
    public void adjustConfig(ServerReport report) {
        alpnSupported = report.getSupportedExtensions().contains(ExtensionType.ALPN);
    }

    @Override
    protected void mergeData(ServerReport report) {
        if ((this.strictSni == TestResults.TRUE || this.strictSni == TestResults.FALSE)
            && (this.strictAlpn == TestResults.TRUE || this.strictAlpn == TestResults.FALSE)) {
            TestResult alpacaMitigated;
            if (this.strictAlpn == TestResults.TRUE && this.strictSni == TestResults.TRUE)
                alpacaMitigated = TestResults.TRUE;
            else if (this.strictAlpn == TestResults.TRUE || this.strictSni == TestResults.TRUE)
                alpacaMitigated = TestResults.PARTIALLY;
            else
                alpacaMitigated = TestResults.FALSE;

            super.put(TlsAnalyzedProperty.STRICT_SNI, this.strictSni);
            super.put(TlsAnalyzedProperty.STRICT_ALPN, this.strictAlpn);
            super.put(TlsAnalyzedProperty.ALPACA_MITIGATED, alpacaMitigated);
        } else {
            super.put(TlsAnalyzedProperty.STRICT_SNI, this.strictSni);
            super.put(TlsAnalyzedProperty.STRICT_ALPN, this.strictAlpn);
            super.put(TlsAnalyzedProperty.ALPACA_MITIGATED, TestResults.UNCERTAIN);
        }
    }
}
