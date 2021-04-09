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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import static de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.AlpacaResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class AlpacaProbe extends TlsProbe {

    private boolean alpnSupported;

    public AlpacaProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CROSS_PROTOCOL_ALPACA, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            TestResult strictSni = isSupportingStrictSni();
            TestResult strictAlpn;
            if (!alpnSupported) {
                strictAlpn = TestResult.FALSE;
            } else {
                strictAlpn = isSupportingStrictAlpn();
            }
            return new AlpacaResult(strictAlpn, strictSni);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new AlpacaResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST);
        }
    }

    private Config getBaseConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        // Dont send extensions if we are in sslv2
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
            return TestResult.FALSE;
        } else {
            return TestResult.TRUE;
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
            return TestResult.FALSE;
        } else {
            return TestResult.TRUE;
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.isProbeAlreadyExecuted(ProbeType.EXTENSIONS);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new AlpacaResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        alpnSupported = report.getSupportedExtensions().contains(ExtensionType.ALPN);
    }

}
