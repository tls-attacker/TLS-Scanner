/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.AlpacaResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class AlpacaProbe extends TlsProbe {

    private boolean alpnSupported;

    public AlpacaProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CROSS_PROTOCOL_ALPACA, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
        TestResult strictSni = isSupportingStrictSni();
        TestResult strictAlpn;
        if (!alpnSupported) {
            strictAlpn = TestResult.FALSE;
        } else {
            strictAlpn = isSupportingStrictAlpn();
        }
        return new AlpacaResult(strictAlpn, strictSni);
    }

    private TestResult isSupportingStrictSni() {
        Config tlsConfig = getConfigSelector().getBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
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
        Config tlsConfig = getConfigSelector().getBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
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
