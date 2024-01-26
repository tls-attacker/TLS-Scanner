/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeFalseRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;

/** Test the servers Hello Retry Request */
public class HelloRetryProbe extends TlsServerProbe {

    private TestResult sendsHelloRetryRequest = TestResults.COULD_NOT_TEST;
    private TestResult issuesCookie = TestResults.COULD_NOT_TEST;
    private NamedGroup serversChosenGroup = null;

    public HelloRetryProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HELLO_RETRY, configSelector);
        register(
                TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY,
                TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST,
                TlsAnalyzedProperty.HRR_SELECTED_GROUP);
    }

    @Override
    protected void executeTest() {
        testHelloRetry();
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeFalseRequirement<ServerReport>(ProtocolType.DTLS)
                .and(new ProbeRequirement<>(TlsProbeType.PROTOCOL_VERSION))
                .and(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_TLS_1_3));
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    private void testHelloRetry() {
        Config tlsConfig = configSelector.getTls13BaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        // enforce HRR by sending empty key share
        tlsConfig.setDefaultClientKeyShareNamedGroups(new LinkedList<>());
        State state = new State(tlsConfig);
        executeState(state);
        sendsHelloRetryRequest = TestResults.FALSE;
        issuesCookie = TestResults.FALSE;
        if (WorkflowTraceResultUtil.didReceiveMessage(
                        state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO)
                && ((ServerHelloMessage)
                                WorkflowTraceResultUtil.getFirstReceivedMessage(
                                        state.getWorkflowTrace(),
                                        HandshakeMessageType.SERVER_HELLO))
                        .isTls13HelloRetryRequest()) {
            sendsHelloRetryRequest = TestResults.TRUE;
            serversChosenGroup = state.getTlsContext().getSelectedGroup();
            if (((ServerHelloMessage)
                            WorkflowTraceResultUtil.getFirstReceivedMessage(
                                    state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO))
                    .containsExtension(ExtensionType.COOKIE)) {
                issuesCookie = TestResults.TRUE;
            }
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        if (issuesCookie != null) {
            put(TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY, issuesCookie);
        } else {
            put(TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY, TestResults.ERROR_DURING_TEST);
        }
        if (sendsHelloRetryRequest != null) {
            put(TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST, sendsHelloRetryRequest);
        } else {
            put(TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST, TestResults.ERROR_DURING_TEST);
        }
        put(TlsAnalyzedProperty.HRR_SELECTED_GROUP, serversChosenGroup);
    }
}
