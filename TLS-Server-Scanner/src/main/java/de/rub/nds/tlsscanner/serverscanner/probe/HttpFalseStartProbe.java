/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.HttpFalseStartResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class HttpFalseStartProbe extends TlsServerProbe<ConfigSelector, ServerReport, HttpFalseStartResult> {

    public HttpFalseStartProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HTTP_FALSE_START, configSelector);
    }

    @Override
    public HttpFalseStartResult executeTest() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setHttpsParsingEnabled(true);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(tlsConfig.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(
            new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage(), new HttpsRequestMessage(tlsConfig)));
        trace.addTlsAction(
            new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage(), new HttpsResponseMessage()));

        State state = new State(tlsConfig, trace);
        executeState(state);

        boolean receivedServerFinishedMessage = false;
        ReceivingAction action = trace.getLastReceivingAction();
        if (action.getReceivedMessages() != null) {
            for (ProtocolMessage message : action.getReceivedMessages()) {
                if (message instanceof HttpsResponseMessage) {
                    // if http response was received the server handled the
                    // false start
                    return new HttpFalseStartResult(TestResults.TRUE);
                } else if (message instanceof FinishedMessage) {
                    receivedServerFinishedMessage = true;
                }
            }
        }
        if (!receivedServerFinishedMessage) {
            // server sent no finished message, false start messed up the
            // handshake
            return new HttpFalseStartResult(TestResults.FALSE);
        }
        // received no http response -> maybe server did not understand
        // request
        return new HttpFalseStartResult(TestResults.UNCERTAIN);
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return report.getResult(TlsAnalyzedProperty.SUPPORTS_HTTPS) == TestResults.TRUE
            && configSelector.foundWorkingConfig();
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    public HttpFalseStartResult getCouldNotExecuteResult() {
        return new HttpFalseStartResult(TestResults.COULD_NOT_TEST);
    }
}
