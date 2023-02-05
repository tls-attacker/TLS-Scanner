/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.http.HttpRequestMessage;
import de.rub.nds.tlsattacker.core.http.HttpResponseMessage;
import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
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
import de.rub.nds.tlsscanner.core.probe.requirements.PropertyRequirement;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.WorkingConfigRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;
import java.util.LinkedList;

public class HttpFalseStartProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private TestResult supportsFalseStart = TestResults.COULD_NOT_TEST;

    public HttpFalseStartProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HTTP_FALSE_START, configSelector);
        register(TlsAnalyzedProperty.SUPPORTS_HTTP_FALSE_START);
    }

    @Override
    public void executeTest() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setDefaultLayerConfiguration(LayerConfiguration.HTTPS);

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace trace =
                factory.createTlsEntryWorkflowTrace(tlsConfig.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(new SendAction(new HttpRequestMessage()));
        trace.addTlsAction(
                new ReceiveAction(
                        new LinkedList<>(
                                Arrays.asList(
                                        new ChangeCipherSpecMessage(), new FinishedMessage())),
                        new LinkedList<>(Arrays.asList(new HttpResponseMessage()))));
        State state = new State(tlsConfig, trace);
        executeState(state);

        boolean receivedServerFinishedMessage = false;
        ReceivingAction action = trace.getLastReceivingAction();

        if (action.getReceivedMessages() != null) {
            receivedServerFinishedMessage =
                    action.getReceivedMessages().stream()
                            .anyMatch(FinishedMessage.class::isInstance);
        }
        supportsFalseStart = TestResults.UNCERTAIN;
        if (action.getReceivedHttpMessages() != null
                && !action.getReceivedHttpMessages().isEmpty()) {
            // review once HTTP layer is re-implemented to ensure that
            // other app data does not appear as http response
            supportsFalseStart = TestResults.TRUE;
        } else if (!receivedServerFinishedMessage) {
            supportsFalseStart = TestResults.FALSE;
        }
    }

    @Override
    protected Requirement getRequirements() {
        return new PropertyRequirement(TlsAnalyzedProperty.SUPPORTS_HTTPS).requires(new WorkingConfigRequirement(configSelector));
    }

    // public boolean canBeExecuted(ServerReport report) {
    // return report.getResult(TlsAnalyzedProperty.SUPPORTS_HTTPS) == TestResults.TRUE
    // && configSelector.foundWorkingConfig();

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_HTTP_FALSE_START, supportsFalseStart);
    }
}
