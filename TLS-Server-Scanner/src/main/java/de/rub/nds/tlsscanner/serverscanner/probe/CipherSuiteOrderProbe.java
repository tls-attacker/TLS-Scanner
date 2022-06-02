/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class CipherSuiteOrderProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private TestResult enforced;

    public CipherSuiteOrderProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CIPHER_SUITE_ORDER, configSelector);
        register(TlsAnalyzedProperty.ENFORCES_CS_ORDERING);
    }

    @Override
    public void executeTest() {
        List<CipherSuite> toTestList = new LinkedList<>();
        toTestList.addAll(Arrays.asList(CipherSuite.values()));
        toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
        toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        CipherSuite firstSelectedCipherSuite = getSelectedCipherSuite(toTestList);
        Collections.reverse(toTestList);
        CipherSuite secondSelectedCipherSuite = getSelectedCipherSuite(toTestList);
        enforced = (firstSelectedCipherSuite == secondSelectedCipherSuite) ? TestResults.TRUE : TestResults.FALSE;
    }

    public CipherSuite getSelectedCipherSuite(List<CipherSuite> toTestList) {
        Config tlsConfig = configSelector.getBaseConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setDefaultClientSupportedCipherSuites(toTestList);
        configSelector.repairConfig(tlsConfig);
        State state = new State(tlsConfig);
        executeState(state);
        return state.getTlsContext().getSelectedCipherSuite();
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    protected Requirement getRequirements() {
        return Requirement.NO_REQUIREMENT;
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.ENFORCES_CS_ORDERING, enforced);
    }
}
