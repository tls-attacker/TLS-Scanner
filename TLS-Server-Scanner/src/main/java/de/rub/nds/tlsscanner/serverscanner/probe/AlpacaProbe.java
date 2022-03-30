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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResults;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.AlpacaResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.requirements.ProbeRequirement;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class AlpacaProbe extends TlsProbe {

    private boolean alpnSupported;
    private TestResult strictSni;
    private TestResult strictAlpn;

    public AlpacaProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CROSS_PROTOCOL_ALPACA, scannerConfig);
        super.properties.add(AnalyzedProperty.STRICT_SNI);
        super.properties.add(AnalyzedProperty.STRICT_ALPN);
        super.properties.add(AnalyzedProperty.ALPACA_MITIGATED);
    }

    @Override
    public void executeTest() {
        strictSni = isSupportingStrictSni();
        if (!alpnSupported) {
            strictAlpn = TestResults.FALSE;
        } else {
            strictAlpn = isSupportingStrictAlpn();
        }
        return;
    }

    private Config getBaseConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
        cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddAlpnExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setStopActionsAfterIOException(true);
        List<NamedGroup> nameGroups = Arrays.asList(NamedGroup.values());
        tlsConfig.setDefaultClientNamedGroups(nameGroups);
        return tlsConfig;
    }

    private TestResult isSupportingStrictSni() {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.getDefaultClientConnection().setHostname("notarealtls-attackerhost.com");
        tlsConfig.setAddAlpnExtension(false);
        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResults.FALSE;
        } else {
            return TestResults.TRUE;
        }
    }

    private TestResult isSupportingStrictAlpn() {
        Config tlsConfig = getBaseConfig();
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setAddAlpnExtension(true);
        tlsConfig.setDefaultProposedAlpnProtocols("NOT an ALPN protocol");

        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return TestResults.FALSE;
        } else {
            return TestResults.TRUE;
        }
    }

    @Override
    protected ProbeRequirement getRequirements(SiteReport report) {
        return new ProbeRequirement(report).requireProbeTypes(ProbeType.EXTENSIONS);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new AlpacaResult(TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        alpnSupported = report.getSupportedExtensions().contains(ExtensionType.ALPN);
    }

	@Override
	protected void mergeData(SiteReport report) {
		if ((strictSni == TestResults.TRUE || strictSni == TestResults.FALSE)
	            && (strictAlpn == TestResults.TRUE || strictAlpn == TestResults.FALSE)) {
	            TestResult alpacaMitigated;
	            if (strictAlpn == TestResults.TRUE && strictSni == TestResults.TRUE)
	                alpacaMitigated = TestResults.TRUE;
	            else if (strictAlpn == TestResults.TRUE || strictSni == TestResults.TRUE) 
	                alpacaMitigated = TestResults.PARTIALLY;
	            else 
	                alpacaMitigated = TestResults.FALSE;
	    
	            super.setPropertyReportValue(AnalyzedProperty.STRICT_SNI, strictSni);
	            super.setPropertyReportValue(AnalyzedProperty.STRICT_ALPN, strictAlpn);
	            super.setPropertyReportValue(AnalyzedProperty.ALPACA_MITIGATED, alpacaMitigated);
	        } else {
	        	super.setPropertyReportValue(AnalyzedProperty.STRICT_SNI, strictSni);
	        	super.setPropertyReportValue(AnalyzedProperty.STRICT_ALPN, strictAlpn);
	        	super.setPropertyReportValue(AnalyzedProperty.ALPACA_MITIGATED, TestResults.UNCERTAIN);
	        }		
	}
}
