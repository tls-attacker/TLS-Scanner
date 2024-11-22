/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.OrRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.closing.ConnectionClosingUtils;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeTrueRequirement;
import java.util.List;

public class ConnectionClosingProbe extends TlsClientProbe {

    private long closedAfterFinishedDelta = ConnectionClosingUtils.NO_RESULT;
    private long closedAfterAppDataDelta = ConnectionClosingUtils.NO_RESULT;

    public ConnectionClosingProbe(
            ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.CONNECTION_CLOSING_DELTA, scannerConfig);
        register(
                TlsAnalyzedProperty.CLOSED_AFTER_FINISHED_DELTA,
                TlsAnalyzedProperty.CLOSED_AFTER_APP_DATA_DELTA);
    }

    @Override
    protected void mergeData(ClientReport report) {
        put(TlsAnalyzedProperty.CLOSED_AFTER_APP_DATA_DELTA, closedAfterAppDataDelta);
        put(TlsAnalyzedProperty.CLOSED_AFTER_FINISHED_DELTA, closedAfterFinishedDelta);
    }

    @Override
    protected void executeTest() {
        // TODO extend with HTTP app data
        Config tlsConfig = scannerConfig.createConfig();
        WorkflowTrace handshakeOnly =
                ConnectionClosingUtils.getWorkflowTrace(tlsConfig, RunningModeType.SERVER);
        WorkflowTrace handshakeWithAppData =
                ConnectionClosingUtils.getWorkflowTrace(tlsConfig, RunningModeType.SERVER);
        handshakeWithAppData.addTlsAction(new SendAction(new ApplicationMessage()));
        State runningState = new State(tlsConfig, handshakeOnly);
        executeState(runningState);
        closedAfterFinishedDelta = ConnectionClosingUtils.evaluateClosingDelta(runningState);
        runningState = new State(tlsConfig, handshakeWithAppData);
        executeState(runningState);
        closedAfterAppDataDelta = ConnectionClosingUtils.evaluateClosingDelta(runningState);
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new OrRequirement<ClientReport>(
                List.of(
                        new ProtocolTypeTrueRequirement<>(ProtocolType.TLS),
                        new ProtocolTypeTrueRequirement<>(ProtocolType.STARTTLS)));
    }

    @Override
    public void adjustConfig(ClientReport report) {}
}
