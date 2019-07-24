/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.result.CipherSuiteOrderResult;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CiphersuiteOrderProbe extends TlsProbe {

    public CiphersuiteOrderProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CIPHERSUITE_ORDER, config, 0);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<CipherSuite> toTestList = new LinkedList<>();
            toTestList.addAll(Arrays.asList(CipherSuite.values()));
            toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
            toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            CipherSuite firstSelectedCipherSuite = getSelectedCipherSuite(toTestList);
            Collections.reverseOrder();
            CipherSuite secondSelectedCipherSuite = getSelectedCipherSuite(toTestList);
            return new CipherSuiteOrderResult(firstSelectedCipherSuite == secondSelectedCipherSuite ? TestResult.TRUE : TestResult.FALSE);
        } catch(Exception e) {
            return new CipherSuiteOrderResult(TestResult.ERROR_DURING_TEST);
        }
    }

    public CipherSuite getSelectedCipherSuite(List<CipherSuite> toTestList) {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setEarlyStop(true);
        tlsConfig.setDefaultClientSupportedCiphersuites(toTestList);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        tlsConfig.setStopActionsAfterFatal(true);
        List<NamedGroup> namedGroups = Arrays.asList(NamedGroup.values());
        tlsConfig.setDefaultClientNamedGroups(namedGroups);
        State state = new State(tlsConfig);
        executeState(state);
        return state.getTlsContext().getSelectedCipherSuite();
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new CipherSuiteOrderResult(TestResult.COULD_NOT_TEST);
    }
}
