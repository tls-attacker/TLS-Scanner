/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.GreaseResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class GreaseProbe extends TlsProbe {

    public GreaseProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.GREASE, config);
    }

    @Override
    public ProbeResult executeTest() {
        TestResult toleratesGreaseSignatureAndHashAlgorithm = getToleratesGreaseSignatureAndHashAlgorithm();
        TestResult toleratesGreaseNamedGroup = getToleratesGreaseNamedGroup();
        TestResult toleratesGreaseCipherSuite = getToleratesGreaseCipherSuite();

        return new GreaseResult(toleratesGreaseCipherSuite, toleratesGreaseNamedGroup,
                toleratesGreaseSignatureAndHashAlgorithm);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    private TestResult getToleratesGreaseSignatureAndHashAlgorithm() {
        Config config = getTestConfig();
        Arrays.asList(SignatureAndHashAlgorithm.values()).stream()
                .filter(algorithm -> algorithm.isGrease())
                .forEach(greaseAlgorithm -> config.getDefaultClientSupportedSignatureAndHashAlgorithms().add(greaseAlgorithm));
        
        State state = new State(config);
        executeState(state);
        if(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResult.TRUE;
        }
        return TestResult.FALSE;
    }

    private TestResult getToleratesGreaseNamedGroup() {
        Config config = getTestConfig();
        Arrays.asList(NamedGroup.values()).stream()
                .filter(group -> group.isGrease())
                .forEach(greaseGroup -> config.getDefaultClientNamedGroups().add(greaseGroup));
        
        State state = new State(config);
        executeState(state);
        if(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResult.TRUE;
        }
        return TestResult.FALSE;
    }

    private TestResult getToleratesGreaseCipherSuite() {
        Config config = getTestConfig();
        Arrays.asList(CipherSuite.values()).stream()
                .filter(cipherSuite -> cipherSuite.isGrease())
                .forEach(greaseCipher -> config.getDefaultClientSupportedCipherSuites().add(greaseCipher));
        
        State state = new State(config);
        executeState(state);
        if(WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResult.TRUE;
        }
        return TestResult.FALSE;
    }

    private Config getTestConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        return tlsConfig;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new GreaseResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

}
