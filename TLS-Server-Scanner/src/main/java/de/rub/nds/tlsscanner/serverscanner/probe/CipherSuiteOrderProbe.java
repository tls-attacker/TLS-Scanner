/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.CipherSuiteOrderResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public class CipherSuiteOrderProbe extends TlsProbe {

    public CipherSuiteOrderProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CIPHER_SUITE_ORDER, config);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<CipherSuite> toTestList = new LinkedList<>();
            toTestList.addAll(Arrays.asList(CipherSuite.values()));
            toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
            toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            CipherSuite firstSelectedCipherSuite = getSelectedCipherSuite(toTestList);
            Collections.reverse(toTestList);
            CipherSuite secondSelectedCipherSuite = getSelectedCipherSuite(toTestList);
            return new CipherSuiteOrderResult(
                firstSelectedCipherSuite == secondSelectedCipherSuite ? TestResult.TRUE : TestResult.FALSE);
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new CipherSuiteOrderResult(TestResult.ERROR_DURING_TEST);
        }
    }

    public CipherSuite getSelectedCipherSuite(List<CipherSuite> toTestList) {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setEarlyStop(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(toTestList);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(true);
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
