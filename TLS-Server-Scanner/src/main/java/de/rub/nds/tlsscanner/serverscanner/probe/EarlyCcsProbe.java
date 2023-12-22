/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.EarlyCcsAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeFalseRequirement;
import de.rub.nds.tlsscanner.serverscanner.probe.earlyccs.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.WorkingConfigRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class EarlyCcsProbe extends TlsServerProbe {

    private EarlyCcsVulnerabilityType earlyCcsVulnerabilityType;

    public EarlyCcsProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.EARLY_CCS, configSelector);
        register(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS);
    }

    @Override
    protected void executeTest() {
        if (checkTargetVersion(TargetVersion.OPENSSL_1_0_0) == TestResults.TRUE) {
            earlyCcsVulnerabilityType = EarlyCcsVulnerabilityType.VULN_NOT_EXPLOITABLE;
        }
        if (checkTargetVersion(TargetVersion.OPENSSL_1_0_1) == TestResults.TRUE) {
            earlyCcsVulnerabilityType = EarlyCcsVulnerabilityType.VULN_EXPLOITABLE;
        }
        earlyCcsVulnerabilityType = EarlyCcsVulnerabilityType.NOT_VULNERABLE;
    }

    private TestResults checkTargetVersion(TargetVersion targetVersion) {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setFiltersKeepUserSettings(false);

        State state = new State(tlsConfig, getTrace(tlsConfig, targetVersion));
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), ProtocolMessageType.ALERT)) {
            LOGGER.debug("Not vulnerable (definitely), Alert message found");
            return TestResults.FALSE;
        } else if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.FINISHED)) {
            LOGGER.debug("Vulnerable (definitely), Finished message found");
            return TestResults.TRUE;
        } else {
            LOGGER.debug("Not vulnerable (probably), No Finished message found, yet also no alert");
            return TestResults.FALSE;
        }
    }

    private WorkflowTrace getTrace(Config tlsConfig, TargetVersion targetVersion) {
        WorkflowTrace workflowTrace =
                new WorkflowConfigurationFactory(tlsConfig)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        workflowTrace.addTlsAction(new SendAction(new ChangeCipherSpecMessage()));
        workflowTrace.addTlsAction(new ChangeMasterSecretAction(new byte[0]));
        workflowTrace.addTlsAction(new ActivateEncryptionAction());
        workflowTrace.addTlsAction(
                new EarlyCcsAction(targetVersion == TargetVersion.OPENSSL_1_0_0));
        if (targetVersion != TargetVersion.OPENSSL_1_0_0) {
            workflowTrace.addTlsAction(new ChangeMasterSecretAction(new byte[0]));
        }
        workflowTrace.addTlsAction(new SendAction(new FinishedMessage()));
        workflowTrace.addTlsAction(
                new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        return workflowTrace;
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    protected void mergeData(ServerReport report) {
        if (earlyCcsVulnerabilityType == null) {
            put(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS, TestResults.COULD_NOT_TEST);
        } else {
            switch (earlyCcsVulnerabilityType) {
                case VULN_EXPLOITABLE:
                case VULN_NOT_EXPLOITABLE:
                    put(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS, TestResults.TRUE);
                    break;
                case NOT_VULNERABLE:
                    put(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS, TestResults.FALSE);
                    break;
                case UNKNOWN:
                    put(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS, TestResults.COULD_NOT_TEST);
            }
        }
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeFalseRequirement<ServerReport>(ProtocolType.DTLS)
                .and(new WorkingConfigRequirement(configSelector));
    }

    private enum TargetVersion {
        OPENSSL_1_0_0,
        OPENSSL_1_0_1
    }
}
