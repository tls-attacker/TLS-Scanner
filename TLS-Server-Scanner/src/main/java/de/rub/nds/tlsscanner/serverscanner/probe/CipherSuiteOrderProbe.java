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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.CipherSuiteOrderResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class CipherSuiteOrderProbe extends TlsProbe {

    public CipherSuiteOrderProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CIPHER_SUITE_ORDER, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
        List<CipherSuite> toTestList = new LinkedList<>();
        toTestList.addAll(Arrays.asList(CipherSuite.values()));
        toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
        toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        CipherSuite firstSelectedCipherSuite = getSelectedCipherSuite(toTestList);
        Collections.reverse(toTestList);
        CipherSuite secondSelectedCipherSuite = getSelectedCipherSuite(toTestList);
        return new CipherSuiteOrderResult(
            firstSelectedCipherSuite == secondSelectedCipherSuite ? TestResult.TRUE : TestResult.FALSE);
    }

    public CipherSuite getSelectedCipherSuite(List<CipherSuite> toTestList) {
        Config tlsConfig = getConfigSelector().getBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setDefaultClientSupportedCipherSuites(toTestList);
        getConfigSelector().repairConfig(tlsConfig);
        State state = new State(tlsConfig);
        executeState(state);
        return state.getTlsContext().getSelectedCipherSuite();
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
        return new CipherSuiteOrderResult(TestResult.COULD_NOT_TEST);
    }
}
