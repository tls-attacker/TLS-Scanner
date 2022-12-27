/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceMutator;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeWriteSequenceNumberAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerCertificateAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.Arrays;

public class DtlsHelloVerifyRequestProbe extends TlsClientProbe<ClientScannerConfig, ClientReport> {

	private TestResult acceptsLegacyServerVersionMismatch;
	private TestResult acceptsHvrSequenceNumberMismatch;
	private TestResult acceptsServerHelloSequenceNumberMismatch;
	private TestResult hasClientHelloMismatch;
	private TestResult acceptsEmptyCookie;

	public DtlsHelloVerifyRequestProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
		super(executor, TlsProbeType.DTLS_HELLO_VERIFY_REQUEST, scannerConfig);
		register(TlsAnalyzedProperty.ACCEPTS_HVR_LEGACY_SERVER_VERSION_MISMATCH,
				TlsAnalyzedProperty.ACCEPTS_HVR_RECORD_SEQUENCE_NUMBER_MISMATCH,
				TlsAnalyzedProperty.ACCEPTS_SERVER_HELLO_RECORD_SEQUENCE_NUMBER_MISMATCH,
				TlsAnalyzedProperty.HAS_CLIENT_HELLO_MISMATCH, TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE);
	}

	@Override
	public void executeTest() {
		acceptsLegacyServerVersionMismatch = acceptsLegacyServerVersionMismatch();
		acceptsHvrSequenceNumberMismatch = acceptsHvrSequenceNumberMismatch();
		acceptsServerHelloSequenceNumberMismatch = acceptsServerHelloSequenceNumberMismatch();
		hasClientHelloMismatch = hasClientHelloMismatch();
		acceptsEmptyCookie = acceptsEmptyCookie();
	}

	private TestResult acceptsLegacyServerVersionMismatch() {
		Config config = scannerConfig.createConfig();

		WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HELLO,
				RunningModeType.SERVER);
		HelloVerifyRequestMessage hvrMessage = new HelloVerifyRequestMessage(config);
		hvrMessage.setProtocolVersion(Modifiable.explicit(ProtocolVersion.DTLS10.getValue()));
		WorkflowTraceMutator.replaceSendingMessage(trace, HandshakeMessageType.HELLO_VERIFY_REQUEST, hvrMessage);
		ServerHelloMessage serverHello = new ServerHelloMessage(config);
		serverHello.setProtocolVersion(Modifiable.explicit(ProtocolVersion.DTLS12.getValue()));
		WorkflowTraceMutator.replaceSendingMessage(trace, HandshakeMessageType.SERVER_HELLO, serverHello);
		trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

		State state = new State(config, trace);
		executeState(state);
		if (state.getWorkflowTrace().executedAsPlanned()) {
			return TestResults.TRUE;
		} else {
			return TestResults.FALSE;
		}
	}

	private TestResult acceptsHvrSequenceNumberMismatch() {
		Config config = scannerConfig.createConfig();

		WorkflowTrace trace = new WorkflowConfigurationFactory(config)
				.createTlsEntryWorkflowTrace(config.getDefaultServerConnection());
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
		trace.addTlsAction(new ChangeWriteSequenceNumberAction(5));
		trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage(config)));
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
		trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
		trace.addTlsAction(new SendDynamicServerCertificateAction());
		trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
		trace.addTlsAction(new SendAction(new ServerHelloDoneMessage(config)));
		trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

		State state = new State(config, trace);
		executeState(state);
		if (state.getWorkflowTrace().executedAsPlanned()) {
			return TestResults.TRUE;
		} else {
			return TestResults.FALSE;
		}
	}

	private TestResult acceptsServerHelloSequenceNumberMismatch() {
		Config config = scannerConfig.createConfig();

		WorkflowTrace trace = new WorkflowConfigurationFactory(config)
				.createTlsEntryWorkflowTrace(config.getDefaultServerConnection());
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
		trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage(config)));
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
		trace.addTlsAction(new ChangeWriteSequenceNumberAction(5));
		trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
		trace.addTlsAction(new SendDynamicServerCertificateAction());
		trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
		trace.addTlsAction(new SendAction(new ServerHelloDoneMessage(config)));
		trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

		State state = new State(config, trace);
		executeState(state);
		if (state.getWorkflowTrace().executedAsPlanned()) {
			return TestResults.TRUE;
		} else {
			return TestResults.FALSE;
		}
	}

	private TestResult hasClientHelloMismatch() {
		Config config = scannerConfig.createConfig();

		WorkflowTrace trace = new WorkflowTrace();
		ReceiveAction firstReceiveAction = new ReceiveAction(new ClientHelloMessage());
		trace.addTlsAction(firstReceiveAction);
		trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage(config)));
		ReceiveAction secondReceiveAction = new ReceiveAction(new ClientHelloMessage());
		trace.addTlsAction(secondReceiveAction);

		State state = new State(config, trace);
		executeState(state);
		if (state.getWorkflowTrace().executedAsPlanned()) {
			ClientHelloMessage firstClientHello = (ClientHelloMessage) firstReceiveAction.getReceivedMessages().get(0);
			ClientHelloMessage secondClientHello = (ClientHelloMessage) secondReceiveAction.getReceivedMessages()
					.get(0);
			boolean versionMatch = Arrays.equals(firstClientHello.getProtocolVersion().getValue(),
					secondClientHello.getProtocolVersion().getValue());
			boolean randomMatch = Arrays.equals(firstClientHello.getRandom().getValue(),
					secondClientHello.getRandom().getValue());
			boolean sessionIdMatch = Arrays.equals(firstClientHello.getSessionId().getValue(),
					secondClientHello.getSessionId().getValue());
			boolean cipherSuitesMatch = Arrays.equals(firstClientHello.getCipherSuites().getValue(),
					secondClientHello.getCipherSuites().getValue());
			boolean compressionsMatch = Arrays.equals(firstClientHello.getCompressions().getValue(),
					secondClientHello.getCompressions().getValue());
			if (versionMatch && randomMatch && sessionIdMatch && cipherSuitesMatch && compressionsMatch) {
				return TestResults.FALSE;
			} else {
				return TestResults.TRUE;
			}
		} else {
			return TestResults.ERROR_DURING_TEST;
		}
	}

	private TestResult acceptsEmptyCookie() {
		Config config = scannerConfig.createConfig();
		config.setDtlsDefaultCookieLength(0);

		WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HELLO,
				RunningModeType.SERVER);
		trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

		State state = new State(config, trace);
		executeState(state);
		if (state.getWorkflowTrace().executedAsPlanned()) {
			return TestResults.TRUE;
		} else {
			return TestResults.FALSE;
		}
	}

	@Override
	public void adjustConfig(ClientReport report) {
	}

	@Override
	protected void mergeData(ClientReport report) {
		put(TlsAnalyzedProperty.ACCEPTS_HVR_LEGACY_SERVER_VERSION_MISMATCH, acceptsLegacyServerVersionMismatch);
		put(TlsAnalyzedProperty.ACCEPTS_HVR_RECORD_SEQUENCE_NUMBER_MISMATCH, acceptsHvrSequenceNumberMismatch);
		put(TlsAnalyzedProperty.ACCEPTS_SERVER_HELLO_RECORD_SEQUENCE_NUMBER_MISMATCH,
				acceptsServerHelloSequenceNumberMismatch);
		put(TlsAnalyzedProperty.HAS_CLIENT_HELLO_MISMATCH, hasClientHelloMismatch);
		put(TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE, acceptsEmptyCookie);
	}

	@Override
	protected Requirement getRequirements() {
		return Requirement.NO_REQUIREMENT;
	}
}
