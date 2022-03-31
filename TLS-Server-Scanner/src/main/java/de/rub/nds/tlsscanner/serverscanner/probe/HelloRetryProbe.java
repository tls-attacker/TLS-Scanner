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
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.HelloRetryResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;

/**
 * Test the servers Hello Retry Request
 */
public class HelloRetryProbe extends TlsProbe {

    private TestResult sendsHelloRetryRequest = TestResult.FALSE;
    private TestResult issuesCookie = TestResult.FALSE;

    public HelloRetryProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.HELLO_RETRY, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
        testHelloRetry();
        return new HelloRetryResult(sendsHelloRetryRequest, issuesCookie);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION)
            && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.TRUE;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new HelloRetryResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    private void testHelloRetry() {
        Config tlsConfig = getConfigSelector().getTls13BaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        // enforce HRR by sending empty key share
        tlsConfig.setDefaultClientKeyShareNamedGroups(new LinkedList<>());
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())
            && ((ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO,
                state.getWorkflowTrace())).isTls13HelloRetryRequest()) {
            sendsHelloRetryRequest = TestResult.TRUE;
            if (((ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO,
                state.getWorkflowTrace())).containsExtension(ExtensionType.COOKIE)) {
                issuesCookie = TestResult.TRUE;
            }
        }
    }

}
