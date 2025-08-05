/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.AndRequirement;
import de.rub.nds.scanner.core.probe.requirements.OrRequirement;
import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.ListResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.SetMeasuringActiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.tlsattacker.transport.tcp.timing.TimingClientTcpTransportHandler;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class TlsLatencyProbe extends TlsServerProbe {

    private static final int ITERATIONS_PER_WORKFLOW = 20;
    List<Long> latenciesHello = new LinkedList<>();
    List<Long> latenciesKeyExchange = new LinkedList<>();
    List<CipherSuite> dheCipherSuites;

    public TlsLatencyProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.TLS_LATENCY, configSelector);
        register(TlsAnalyzedProperty.TLS_LATENCY_HELLO);
        register(TlsAnalyzedProperty.TLS_LATENCY_KEY_EXCHANGE);
    }

    @Override
    protected void mergeData(ServerReport report) {
        mergeMeasurements(report, TlsAnalyzedProperty.TLS_LATENCY_HELLO, latenciesHello);
        mergeMeasurements(
                report, TlsAnalyzedProperty.TLS_LATENCY_KEY_EXCHANGE, latenciesKeyExchange);
    }

    public void mergeMeasurements(ServerReport report, TlsAnalyzedProperty type, List<Long> list) {
        if (!list.isEmpty()) {
            report.putResult(type, new ListResult<>(type, List.of(list)));
        } else {
            report.putResult(type, TestResults.COULD_NOT_TEST);
        }
    }

    @Override
    public void executeTest() {
        Config config = configSelector.getBaseConfig();
        if (!dheCipherSuites.isEmpty()) {
            config.setDefaultClientSupportedCipherSuites(dheCipherSuites);
        }
        // fix possible issues caused by limited cipher suites list
        configSelector.repairConfig(config);

        config.getDefaultClientConnection()
                .setTransportHandlerType(TransportHandlerType.TCP_TIMING);
        testShortWorkflowTrace(config);
        testHandshakeWorkflow(config);
    }

    private void testHandshakeWorkflow(Config config) {
        for (int i = 0; i < ITERATIONS_PER_WORKFLOW; i++) {
            WorkflowTrace workflowTrace =
                    new WorkflowConfigurationFactory(config)
                            .createDynamicHandshakeWorkflow(config.getDefaultClientConnection());
            // prevent dynamic CKE from waiting for a response
            workflowTrace.addTlsAction(0, new SetMeasuringActiveAction(false));
            int lastSendIndex =
                    workflowTrace.getTlsActions().indexOf(workflowTrace.getLastSendingAction());
            workflowTrace.addTlsAction(lastSendIndex, new SetMeasuringActiveAction(true));
            State state = new State(config, workflowTrace);
            executeState(state);
            TimingClientTcpTransportHandler transportHandler =
                    (TimingClientTcpTransportHandler) state.getTlsContext().getTransportHandler();
            if (WorkflowTraceResultUtil.didReceiveMessage(
                    workflowTrace, HandshakeMessageType.FINISHED)) {
                latenciesKeyExchange.add(transportHandler.getLastMeasurement());
            } else {
                LOGGER.info("Following trace failed: \n {}", workflowTrace.toString());
            }
        }
    }

    private void testShortWorkflowTrace(Config config) {
        for (int i = 0; i < ITERATIONS_PER_WORKFLOW; i++) {
            WorkflowTrace workflowTrace =
                    new WorkflowConfigurationFactory(config)
                            .createShortHelloWorkflow(config.getDefaultClientConnection());
            State state = new State(config, workflowTrace);
            executeState(state);
            TimingClientTcpTransportHandler transportHandler =
                    (TimingClientTcpTransportHandler) state.getTlsContext().getTransportHandler();
            if (WorkflowTraceResultUtil.didReceiveMessage(
                    workflowTrace, HandshakeMessageType.SERVER_HELLO)) {
                latenciesHello.add(transportHandler.getLastMeasurement());
            } else {
                LOGGER.info("Following trace failed: \n {}", workflowTrace.toString());
            }
        }
    }

    @Override
    public void adjustConfig(ServerReport report) {
        try {
            dheCipherSuites =
                    report.getSupportedCipherSuites().stream()
                            .filter(cipherSuite -> cipherSuite.name().contains("TLS_DHE_"))
                            .collect(Collectors.toList());
        } catch (Exception ex) {
            dheCipherSuites = new LinkedList<>();
        }
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new AndRequirement<>(
                List.of(
                        new ProbeRequirement<>(TlsProbeType.CIPHER_SUITE),
                        new OrRequirement<ServerReport>(
                                List.of(
                                        new ProtocolTypeTrueRequirement<>(ProtocolType.TLS),
                                        new ProtocolTypeTrueRequirement<>(
                                                ProtocolType.STARTTLS)))));
    }
}
