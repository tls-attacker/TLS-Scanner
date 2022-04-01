/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.attacks.actions.EarlyCcsAction;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.earlyccs.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.EarlyCcsResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class EarlyCcsProbe extends TlsProbe {

    public EarlyCcsProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.EARLY_CCS, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
        return new EarlyCcsResult(isVulnerable());
    }

    private EarlyCcsVulnerabilityType isVulnerable() {
        if (checkTargetVersion(TargetVersion.OPENSSL_1_0_0) == TestResult.TRUE) {
            return EarlyCcsVulnerabilityType.VULN_NOT_EXPLOITABLE;
        }
        if (checkTargetVersion(TargetVersion.OPENSSL_1_0_1) == TestResult.TRUE) {
            return EarlyCcsVulnerabilityType.VULN_EXPLOITABLE;
        }
        return EarlyCcsVulnerabilityType.NOT_VULNERABLE;
    }

    private TestResult checkTargetVersion(TargetVersion targetVersion) {
        Config tlsConfig = getConfigSelector().getBaseConfig();
        tlsConfig.setFiltersKeepUserSettings(false);

        State state = new State(tlsConfig, getTrace(tlsConfig, targetVersion));
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.ALERT, state.getWorkflowTrace())) {
            LOGGER.debug("Not vulnerable (definitely), Alert message found");
            return TestResult.FALSE;
        } else if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            LOGGER.debug("Vulnerable (definitely), Finished message found");
            return TestResult.TRUE;
        } else {
            LOGGER.debug("Not vulnerable (probably), No Finished message found, yet also no alert");
            return TestResult.FALSE;
        }
    }

    private WorkflowTrace getTrace(Config tlsConfig, TargetVersion targetVersion) {
        WorkflowTrace workflowTrace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        workflowTrace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(tlsConfig)));
        workflowTrace.addTlsAction(new ChangeMasterSecretAction(new byte[0]));
        workflowTrace.addTlsAction(new ActivateEncryptionAction());
        workflowTrace.addTlsAction(new EarlyCcsAction(targetVersion == TargetVersion.OPENSSL_1_0_0));
        if (targetVersion != TargetVersion.OPENSSL_1_0_0) {
            workflowTrace.addTlsAction(new ChangeMasterSecretAction(new byte[0]));
        }
        workflowTrace.addTlsAction(new SendAction(new FinishedMessage(tlsConfig)));
        workflowTrace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        return workflowTrace;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new EarlyCcsResult(null);
    }

    private enum TargetVersion {
        OPENSSL_1_0_0,
        OPENSSL_1_0_1
    }
}
