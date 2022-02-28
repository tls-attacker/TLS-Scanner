/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResults;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.SignatureHashAlgorithmOrderResult;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class SignatureHashAlgorithmOrderProbe extends TlsProbe {

    public SignatureHashAlgorithmOrderProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.SIGNATURE_HASH_ALGORITHM_ORDER, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        List<SignatureAndHashAlgorithm> toTestList = new LinkedList<>();
        toTestList.addAll(Arrays.asList(SignatureAndHashAlgorithm.values()));
        SignatureAndHashAlgorithm firstSelectedSignatureAndHashAlgorithm =
            getSelectedSignatureAndHashAlgorithm(toTestList);
        Collections.reverse(toTestList);
        SignatureAndHashAlgorithm secondSelectedSignatureAndHashAlgorithm =
            getSelectedSignatureAndHashAlgorithm(toTestList);

        return new SignatureHashAlgorithmOrderResult(
            firstSelectedSignatureAndHashAlgorithm == secondSelectedSignatureAndHashAlgorithm ? TestResults.TRUE
                : TestResults.FALSE);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return !report.isProbeAlreadyExecuted(ProbeType.SIGNATURE_HASH_ALGORITHM_ORDER);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new SignatureHashAlgorithmOrderResult(TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    private SignatureAndHashAlgorithm getSelectedSignatureAndHashAlgorithm(List<SignatureAndHashAlgorithm> list) {
        Config config = getScannerConfig().createConfig();

        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(list);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);

        config.setEarlyStop(true);
        config.setStopActionsAfterIOException(true);
        config.setEnforceSettings(true);
        config.setQuickReceive(true);
        config.setStopActionsAfterFatal(true);
        config.setStopReceivingAfterFatal(true);

        State state = new State(config);
        executeState(state);
        return state.getTlsContext().getSelectedSignatureAndHashAlgorithm();
    }

}
