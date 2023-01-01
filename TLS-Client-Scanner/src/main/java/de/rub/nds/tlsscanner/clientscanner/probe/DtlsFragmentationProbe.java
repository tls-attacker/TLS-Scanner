/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

public class DtlsFragmentationProbe extends TlsClientProbe<ClientScannerConfig, ClientReport> {

	private static final int INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN = 200;

	private TestResult supportsDirectly;
	private TestResult supportsDirectlyIndPackets;
	private TestResult supportsAfterCookieExchange;
	private TestResult supportsAfterCookieExchangeIndPackets;
	private TestResult supportsWithExtension;
	private TestResult supportsWithExtensionIndPackets;

	public DtlsFragmentationProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
		super(executor, TlsProbeType.DTLS_FRAGMENTATION, scannerConfig);
		register(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION,
				TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION,
				TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS,
				TlsAnalyzedProperty.DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION);
	}

	@Override
	public void executeTest() {
		supportsDirectly = supportsFragmentationDirectly(false);
		supportsDirectlyIndPackets = supportsFragmentationDirectly(true);
		supportsAfterCookieExchange = supportsFragmentationAfterCookieExchange(false);
		supportsAfterCookieExchangeIndPackets = supportsFragmentationAfterCookieExchange(true);
		supportsWithExtension = supportsFragmentationWithExtension(false);
		supportsWithExtensionIndPackets = supportsFragmentationWithExtension(true);
	}

	private TestResult supportsFragmentationDirectly(boolean individualTransportPackets) {
		Config config = scannerConfig.createConfig();
		config.setDtlsMaximumFragmentLength(15);
		if (individualTransportPackets) {
			config.setIndividualTransportPacketsForFragments(true);
			config.setIndividualTransportPacketCooldown(INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN);
		}

		WorkflowTrace trace = new WorkflowConfigurationFactory(config)
				.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));
		trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));

		State state = new State(config, trace);
		executeState(state);
		if (state.getWorkflowTrace().executedAsPlanned()) {
			return TestResults.TRUE;
		} else {
			return TestResults.FALSE;
		}
	}

	private TestResult supportsFragmentationAfterCookieExchange(boolean individualTransportPackets) {
		Config config = scannerConfig.createConfig();
		if (individualTransportPackets) {
			config.setIndividualTransportPacketsForFragments(true);
			config.setIndividualTransportPacketCooldown(INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN);
		}

		WorkflowTrace trace = new WorkflowConfigurationFactory(config)
				.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));
		trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));
		trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
		SendAction action = new SendAction(new CertificateMessage());
		action.setFragments(new DtlsHandshakeMessageFragment(config, 20), new DtlsHandshakeMessageFragment(config, 20));
		trace.addTlsAction(action);
		trace.addTlsAction(new SendAction(new CertificateMessage()));
		trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
		trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
		trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

		State state = new State(config, trace);
		executeState(state);
		if (state.getWorkflowTrace().executedAsPlanned()) {
			return TestResults.TRUE;
		} else {
			return TestResults.FALSE;
		}
	}

	private TestResult supportsFragmentationWithExtension(boolean individualTransportPackets) {
		Config config = scannerConfig.createConfig();
		config.setAddMaxFragmentLengthExtension(true);
		config.setDefaultMaxFragmentLength(MaxFragmentLength.TWO_11);
		if (individualTransportPackets) {
			config.setIndividualTransportPacketsForFragments(true);
			config.setIndividualTransportPacketCooldown(INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN);
		}

		WorkflowTrace trace = new WorkflowConfigurationFactory(config)
				.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));
		trace.addTlsAction(new SendAction(new HelloVerifyRequestMessage()));
		trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(config)));
		trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
		SendAction action = new SendAction(new CertificateMessage());
		action.setFragments(new DtlsHandshakeMessageFragment(config, 20), new DtlsHandshakeMessageFragment(config, 20));
		trace.addTlsAction(action);
		trace.addTlsAction(new SendAction(new CertificateMessage()));
		trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
		trace.addTlsAction(new SendAction(new ServerHelloDoneMessage()));
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
		if (supportsDirectly == TestResults.TRUE) {
			put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, TestResults.TRUE);
			put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION, TestResults.FALSE);
		} else if (supportsAfterCookieExchange == TestResults.TRUE) {
			put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, TestResults.PARTIALLY);
			put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION, TestResults.FALSE);
		} else if (supportsWithExtension == TestResults.TRUE) {
			put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, TestResults.PARTIALLY);
			put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION, TestResults.TRUE);
		} else {
			put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, TestResults.FALSE);
			put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION, TestResults.FALSE);
		}

		if (supportsDirectlyIndPackets == TestResults.TRUE) {
			put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS, TestResults.TRUE);
			put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION, TestResults.FALSE);
		} else if (supportsAfterCookieExchangeIndPackets == TestResults.TRUE) {
			put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS, TestResults.PARTIALLY);
			put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION, TestResults.FALSE);
		} else if (supportsWithExtensionIndPackets == TestResults.TRUE) {
			put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS, TestResults.PARTIALLY);
			put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION, TestResults.TRUE);
		} else {
			put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS, TestResults.FALSE);
			put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION, TestResults.FALSE);
		}
	}

	@Override
	protected Requirement getRequirements() {
		return Requirement.NO_REQUIREMENT;
	}

}
