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
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.TlsFallbackScsvResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class TlsFallbackScsvProbe extends TlsServerProbe<ConfigSelector, ServerReport, TlsFallbackScsvResult> {

    private ProtocolVersion secondHighestVersion;

    public TlsFallbackScsvProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.TLS_FALLBACK_SCSV, configSelector);
    }

    @Override
    public TlsFallbackScsvResult executeTest() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.getDefaultClientSupportedCipherSuites().add(CipherSuite.TLS_FALLBACK_SCSV);
        tlsConfig.setHighestProtocolVersion(this.secondHighestVersion);

        State state = new State(tlsConfig, getWorkflowTrace(tlsConfig));
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return new TlsFallbackScsvResult(TestResults.TRUE);
        } else {
            LOGGER.debug("Received ServerHelloMessage");
            LOGGER.debug("{}", state.getWorkflowTrace());
            return new TlsFallbackScsvResult(TestResults.FALSE);
        }
    }

    private WorkflowTrace getWorkflowTrace(Config config) {
        WorkflowTrace trace = new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, config.getDefaultRunningMode());
        trace.removeTlsAction(trace.getTlsActions().size() - 1);
        AlertMessage alertMessage = new AlertMessage();
        alertMessage.setDescription(AlertDescription.INAPPROPRIATE_FALLBACK.getValue());
        alertMessage.setLevel(AlertLevel.FATAL.getValue());
        trace.addTlsAction(new ReceiveAction(alertMessage));
        return trace;
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return report.isProbeAlreadyExecuted(TlsProbeType.PROTOCOL_VERSION) && report.getVersions().size() > 1;
    }

    @Override
    public TlsFallbackScsvResult getCouldNotExecuteResult() {
        return new TlsFallbackScsvResult(TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        List<ProtocolVersion> versions = new ArrayList<>(report.getVersions());
        Collections.sort(versions);
        this.secondHighestVersion = versions.get(versions.size() - 2);
    }
}
