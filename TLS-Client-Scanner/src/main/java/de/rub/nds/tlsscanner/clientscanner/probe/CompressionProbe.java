/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import static de.rub.nds.tlsscanner.clientscanner.probe.TlsClientProbe.LOGGER;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.probe.result.CompressionResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.LinkedList;
import java.util.List;

public class CompressionProbe
        extends TlsClientProbe<ClientScannerConfig, ClientReport, CompressionResult> {

    private List<CompressionMethod> clientAdvertisedCompressions = null;

    public CompressionProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.COMPRESSIONS, scannerConfig);
    }

    @Override
    public CompressionResult executeTest() {
        List<CompressionMethod> supportedCompressions = new LinkedList<>();
        for (CompressionMethod compressionMethod : CompressionMethod.values()) {
            LOGGER.debug("Testing compression {}", compressionMethod);

            Config config = scannerConfig.createConfig();
            config.setEnforceSettings(true);
            config.setDefaultServerSupportedCompressionMethods(compressionMethod);
            config.setDefaultSelectedCompressionMethod(compressionMethod);

            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace workflowTrace =
                    factory.createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.SERVER);
            workflowTrace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

            State state = new State(config, workflowTrace);
            executeState(state);

            if (state.getWorkflowTrace().executedAsPlanned()) {
                supportedCompressions.add(compressionMethod);
            }
        }
        TestResult forcedCompression;
        if (clientAdvertisedCompressions != null) {
            if (!clientAdvertisedCompressions.containsAll(supportedCompressions)) {
                forcedCompression = TestResults.TRUE;
            } else {
                forcedCompression = TestResults.FALSE;
            }
        } else {
            forcedCompression = TestResults.UNCERTAIN;
        }
        return new CompressionResult(supportedCompressions, forcedCompression);
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return report.isProbeAlreadyExecuted(TlsProbeType.BASIC);
    }

    @Override
    public CompressionResult getCouldNotExecuteResult() {
        return new CompressionResult(null, TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(ClientReport report) {
        clientAdvertisedCompressions = report.getClientAdvertisedCompressions();
    }
}
