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
import de.rub.nds.scanner.core.probe.requirements.PropertyComparatorRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
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
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class TlsFallbackScsvProbe extends TlsServerProbe {

    private ProtocolVersion secondHighestVersion;
    private TestResult result = TestResults.COULD_NOT_TEST;

    public TlsFallbackScsvProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.TLS_FALLBACK_SCSV, configSelector);
        register(TlsAnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV);
    }

    @Override
    protected void executeTest() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.getDefaultClientSupportedCipherSuites().add(CipherSuite.TLS_FALLBACK_SCSV);
        tlsConfig.setHighestProtocolVersion(this.secondHighestVersion);

        State state = new State(tlsConfig, getWorkflowTrace(tlsConfig));
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            result = TestResults.TRUE;
        } else {
            LOGGER.debug("Received ServerHelloMessage");
            LOGGER.debug("{}", state.getWorkflowTrace());
            result = TestResults.FALSE;
        }
    }

    private WorkflowTrace getWorkflowTrace(Config config) {
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, config.getDefaultRunningMode());
        trace.removeTlsAction(trace.getTlsActions().size() - 1);
        AlertMessage alertMessage = new AlertMessage();
        alertMessage.setDescription(AlertDescription.INAPPROPRIATE_FALLBACK.getValue());
        alertMessage.setLevel(AlertLevel.FATAL.getValue());
        trace.addTlsAction(new ReceiveAction(alertMessage));
        return trace;
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProbeRequirement<ServerReport>(TlsProbeType.PROTOCOL_VERSION)
                .and(
                        new PropertyComparatorRequirement<>(
                                PropertyComparatorRequirement.Operator.GREATER,
                                TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS,
                                1));
    }

    @Override
    public void adjustConfig(ServerReport report) {
        List<ProtocolVersion> versions = new ArrayList<>(report.getSupportedProtocolVersions());
        Collections.sort(versions);
        secondHighestVersion = versions.get(versions.size() - 2);
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV, result);
    }
}
