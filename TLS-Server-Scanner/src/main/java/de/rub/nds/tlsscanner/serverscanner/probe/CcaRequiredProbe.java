/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.WorkingConfigRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class CcaRequiredProbe extends TlsServerProbe {

    private TestResult requiresCca = TestResults.COULD_NOT_TEST;

    public CcaRequiredProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CCA_SUPPORT, configSelector);
        register(TlsAnalyzedProperty.REQUIRES_CCA);
    }

    @Override
    protected void executeTest() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setAutoAdjustCertificate(false);

        WorkflowTrace trace =
                new WorkflowConfigurationFactory(tlsConfig)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        State state = new State(tlsConfig, trace);
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.FINISHED)) {
            requiresCca = TestResults.FALSE;
        } else {
            requiresCca = TestResults.TRUE;
        }
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new PropertyTrueRequirement<ServerReport>(TlsAnalyzedProperty.SUPPORTS_CCA)
                .and(new WorkingConfigRequirement(configSelector));
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.REQUIRES_CCA, requiresCca);
    }
}
