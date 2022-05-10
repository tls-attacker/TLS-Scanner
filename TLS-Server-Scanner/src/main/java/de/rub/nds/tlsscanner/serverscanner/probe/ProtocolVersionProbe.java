/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class ProtocolVersionProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private List<ProtocolVersion> toTestList;
    private List<ProtocolVersion> supportedProtocolVersions;
    private List<ProtocolVersion> unsupportedProtocolVersions;

    public ProtocolVersionProbe(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.PROTOCOL_VERSION, config);
        toTestList = new LinkedList<>();
        if (getScannerConfig().getDtlsDelegate().isDTLS()) {
            toTestList.add(ProtocolVersion.DTLS10);
            toTestList.add(ProtocolVersion.DTLS12);
        } else {
            toTestList.add(ProtocolVersion.SSL2);
            toTestList.add(ProtocolVersion.SSL3);
            toTestList.add(ProtocolVersion.TLS10);
            toTestList.add(ProtocolVersion.TLS11);
            toTestList.add(ProtocolVersion.TLS12);
        }
        super.register(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0, TlsAnalyzedProperty.SUPPORTS_DTLS_1_2,
            TlsAnalyzedProperty.SUPPORTS_SSL_2, TlsAnalyzedProperty.SUPPORTS_SSL_3,
            TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
            TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
            TlsAnalyzedProperty.LIST_SUPPORTED_PROTOCOLVERSIONS);
    }

    @Override
    public void executeTest() {
        this.supportedProtocolVersions = new LinkedList<>();
        this.unsupportedProtocolVersions = new LinkedList<>();

        for (ProtocolVersion version : toTestList) {
            if (isProtocolVersionSupported(version, false))
                this.supportedProtocolVersions.add(version);
            else
                this.unsupportedProtocolVersions.add(version);
        }
        if (this.supportedProtocolVersions.isEmpty()) {
            this.unsupportedProtocolVersions = new LinkedList<>();
            for (ProtocolVersion version : toTestList) {
                if (isProtocolVersionSupported(version, true))
                    this.supportedProtocolVersions.add(version);
                else
                    this.unsupportedProtocolVersions.add(version);
            }
        }
        if (!getScannerConfig().getDtlsDelegate().isDTLS()) {
            if (isTls13Supported())
                this.supportedProtocolVersions.add(ProtocolVersion.TLS13);
            else
                this.unsupportedProtocolVersions.add(ProtocolVersion.TLS13);
        }
    }

    public boolean isProtocolVersionSupported(ProtocolVersion toTest, boolean intolerance) {
        if (toTest == ProtocolVersion.SSL2) {
            return isSSL2Supported();
        }
        Config tlsConfig = getScannerConfig().createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        if (intolerance) {
            cipherSuites.addAll(CipherSuite.getImplemented());
        } else {
            cipherSuites.addAll(Arrays.asList(CipherSuite.values()));
            cipherSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
            cipherSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        }
        tlsConfig.setDefaultSelectedProtocolVersion(toTest);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(cipherSuites);
        tlsConfig.setHighestProtocolVersion(toTest);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        List<NamedGroup> namedGroups = Arrays.asList(NamedGroup.values());

        tlsConfig.setDefaultClientNamedGroups(namedGroups);
        State state = new State(tlsConfig);
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            LOGGER.debug("Did not receive ServerHello Message");
            LOGGER.debug(state.getWorkflowTrace().toString());
            return false;
        } else {
            LOGGER.debug("Received ServerHelloMessage");
            LOGGER.debug(state.getWorkflowTrace().toString());
            LOGGER.debug("Selected Version:" + state.getTlsContext().getSelectedProtocolVersion().name());
            return state.getTlsContext().getSelectedProtocolVersion() == toTest;
        }
    }

    private boolean isSSL2Supported() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.SSL2);
        tlsConfig.setEnforceSettings(true);
        tlsConfig.setQuickReceive(true);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setRecordLayerType(RecordLayerType.BLOB);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(tlsConfig.getDefaultClientConnection());

        trace.addTlsAction(new SendAction(new SSL2ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveAction(new SSL2ServerHelloMessage(tlsConfig)));
        State state = new State(tlsConfig, trace);
        executeState(state);
        return trace.executedAsPlanned();
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    public ProtocolVersionProbe getCouldNotExecuteResult() {
        this.supportedProtocolVersions = null;
        this.unsupportedProtocolVersions = null;
        return this;
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        return ProbeRequirement.NO_REQUIREMENT;
    }

    private boolean isTls13Supported() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(CipherSuite.getImplemented());
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setDefaultClientKeyShareNamedGroups(new LinkedList<>());
        tlsConfig.setAddCertificateStatusRequestExtension(true);
        tlsConfig.setUseFreshRandom(true);
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(
            SignatureAndHashAlgorithm.getTls13SignatureAndHashAlgorithms());
        State state = new State(tlsConfig);
        executeState(state);
        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            LOGGER.debug("Did not receive ServerHello Message");
            LOGGER.debug(state.getWorkflowTrace().toString());
            return false;
        } else {
            LOGGER.debug("Received ServerHelloMessage");
            LOGGER.debug(state.getWorkflowTrace().toString());
            LOGGER.debug("Selected Version:" + state.getTlsContext().getSelectedProtocolVersion().name());
            return state.getTlsContext().getSelectedProtocolVersion() == ProtocolVersion.TLS13;
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        if (this.supportedProtocolVersions != null) {
            super.put(TlsAnalyzedProperty.LIST_SUPPORTED_PROTOCOLVERSIONS,
                new ListResult<ProtocolVersion>(this.supportedProtocolVersions, "SUPPORTED_PROTOCOLVERSIONS"));
            for (ProtocolVersion version : this.supportedProtocolVersions) {
                if (version == ProtocolVersion.DTLS10)
                    super.put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0, TestResults.TRUE);
                if (version == ProtocolVersion.DTLS12)
                    super.put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2, TestResults.TRUE);
                if (version == ProtocolVersion.SSL2)
                    super.put(TlsAnalyzedProperty.SUPPORTS_SSL_2, TestResults.TRUE);
                if (version == ProtocolVersion.SSL3)
                    super.put(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.TRUE);
                if (version == ProtocolVersion.TLS10)
                    super.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResults.TRUE);
                if (version == ProtocolVersion.TLS11)
                    super.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, TestResults.TRUE);
                if (version == ProtocolVersion.TLS12)
                    super.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE);
                if (version == ProtocolVersion.TLS13)
                    super.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE);
            }

            for (ProtocolVersion version : this.unsupportedProtocolVersions) {
                if (version == ProtocolVersion.DTLS10)
                    super.put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0, TestResults.FALSE);
                if (version == ProtocolVersion.DTLS12)
                    super.put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2, TestResults.FALSE);
                if (version == ProtocolVersion.SSL2)
                    super.put(TlsAnalyzedProperty.SUPPORTS_SSL_2, TestResults.FALSE);
                if (version == ProtocolVersion.SSL3)
                    super.put(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.FALSE);
                if (version == ProtocolVersion.TLS10)
                    super.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResults.FALSE);
                if (version == ProtocolVersion.TLS11)
                    super.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, TestResults.FALSE);
                if (version == ProtocolVersion.TLS12)
                    super.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.FALSE);
                if (version == ProtocolVersion.TLS13)
                    super.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.FALSE);
            }
        } else {
            super.put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0, TestResults.COULD_NOT_TEST);
            super.put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2, TestResults.COULD_NOT_TEST);
            super.put(TlsAnalyzedProperty.SUPPORTS_SSL_2, TestResults.COULD_NOT_TEST);
            super.put(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.COULD_NOT_TEST);
            super.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResults.COULD_NOT_TEST);
            super.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, TestResults.COULD_NOT_TEST);
            super.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.COULD_NOT_TEST);
            super.put(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.COULD_NOT_TEST);
        }
        if (!getScannerConfig().getDtlsDelegate().isDTLS()) {
            super.put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0, TestResults.CANNOT_BE_TESTED);
            super.put(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2, TestResults.CANNOT_BE_TESTED);
        }
        super.put(TlsAnalyzedProperty.LIST_SUPPORTED_PROTOCOLVERSIONS,
            new ListResult<ProtocolVersion>(this.supportedProtocolVersions, "SUPPORTED_PROTOCOLVERSIONS"));
    }
}
