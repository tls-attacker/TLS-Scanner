/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.OrRequirement;
import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.http.HttpRequestMessage;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.closing.ConnectionClosingUtils;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.List;

/**
 * Determines when the server closes the connection. It's meant for tests in the lab so we limit the
 * probe. Note that NO_RESULT may indicate that we couldn't identify a closing delta, i.e the server
 * didn't close the connection within our limit or the probe could not be executed.
 */
public class ConnectionClosingProbe extends TlsServerProbe {

    private boolean useHttpAppData = false;
    private long closedAfterFinishedDelta = ConnectionClosingUtils.NO_RESULT;
    private long closedAfterAppDataDelta = ConnectionClosingUtils.NO_RESULT;

    public ConnectionClosingProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CONNECTION_CLOSING_DELTA, configSelector);
        register(
                TlsAnalyzedProperty.CLOSED_AFTER_FINISHED_DELTA,
                TlsAnalyzedProperty.CLOSED_AFTER_APP_DATA_DELTA);
    }

    @Override
    protected void executeTest() {
        Config tlsConfig = configSelector.getAnyWorkingBaseConfig();
        configSelector.repairConfig(tlsConfig);

        WorkflowTrace handshakeOnly =
                ConnectionClosingUtils.getWorkflowTrace(tlsConfig, RunningModeType.CLIENT);
        WorkflowTrace handshakeWithAppData =
                ConnectionClosingUtils.getWorkflowTrace(tlsConfig, RunningModeType.CLIENT);
        if (useHttpAppData) {
            tlsConfig.setDefaultLayerConfiguration(StackConfiguration.HTTPS);
            handshakeWithAppData.addTlsAction(new SendAction(new HttpRequestMessage()));
        } else {
            handshakeWithAppData.addTlsAction(new SendAction(new ApplicationMessage()));
        }
        State runningState = new State(tlsConfig, handshakeOnly);
        executeState(runningState);
        closedAfterFinishedDelta = ConnectionClosingUtils.evaluateClosingDelta(runningState);
        runningState = new State(tlsConfig, handshakeWithAppData);
        executeState(runningState);
        closedAfterAppDataDelta = ConnectionClosingUtils.evaluateClosingDelta(runningState);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        useHttpAppData = report.getResult(TlsAnalyzedProperty.SUPPORTS_HTTPS) == TestResults.TRUE;
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.CLOSED_AFTER_APP_DATA_DELTA, closedAfterAppDataDelta);
        put(TlsAnalyzedProperty.CLOSED_AFTER_FINISHED_DELTA, closedAfterFinishedDelta);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new OrRequirement<ServerReport>(
                        List.of(
                                new ProtocolTypeTrueRequirement<>(ProtocolType.TLS),
                                new ProtocolTypeTrueRequirement<>(ProtocolType.STARTTLS)))
                .and(new ProbeRequirement<>(TlsProbeType.HTTP_HEADER));
    }
}
