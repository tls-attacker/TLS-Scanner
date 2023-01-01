/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.PropertyRequirement;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.CcaCertificateManager;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.constans.CcaCertificateType;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.constans.CcaWorkflowType;
import de.rub.nds.tlsscanner.serverscanner.probe.cca.trace.CcaWorkflowGenerator;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.WorkingConfigRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class CcaRequiredProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private TestResult requiresCca;

    public CcaRequiredProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CCA_SUPPORT, configSelector);
        register(TlsAnalyzedProperty.REQUIRES_CCA);
    }

    @Override
    public void executeTest() {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setAutoSelectCertificate(false);
        CcaCertificateManager ccaCertificateManager =
            new CcaCertificateManager(configSelector.getScannerConfig().getCcaDelegate());
        WorkflowTrace trace = CcaWorkflowGenerator.generateWorkflow(tlsConfig, ccaCertificateManager,
            CcaWorkflowType.CRT_CKE_CCS_FIN, CcaCertificateType.EMPTY);
        State state = new State(tlsConfig, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            requiresCca = TestResults.FALSE;
        } else {
            requiresCca = TestResults.TRUE;
        }
    }

    @Override
    protected Requirement getRequirements() {
        return new PropertyRequirement(TlsAnalyzedProperty.SUPPORTS_CCA)
            .requires(new WorkingConfigRequirement(configSelector));
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.REQUIRES_CCA, requiresCca);
    }
}