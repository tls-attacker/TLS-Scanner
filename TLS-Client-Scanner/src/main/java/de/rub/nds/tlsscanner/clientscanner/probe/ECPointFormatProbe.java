/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.ecpointformat.ECPointFormatUtils;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class ECPointFormatProbe extends TlsClientProbe {

    private Boolean shouldTestTls13;
    private Boolean shouldTestPointFormats;
    private Boolean shouldAddRenegotiationInfo;

    private TestResult completesHandshakeWithUndefined = TestResults.FALSE;

    private List<ECPointFormat> supportedFormats;
    private TestResult tls13SecpCompression;

    private List<CipherSuite> clientAdvertisedCipherSuites = new LinkedList<>();

    public ECPointFormatProbe(
            ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.EC_POINT_FORMAT, scannerConfig);
        register(
                TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT,
                TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME,
                TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2,
                TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION,
                TlsAnalyzedProperty.HANDSHAKES_WITH_UNDEFINED_POINT_FORMAT);
    }

    @Override
    protected void mergeData(ClientReport report) {
        ECPointFormatUtils.mergeInProbe(
                supportedFormats, this, completesHandshakeWithUndefined, tls13SecpCompression);
    }

    @Override
    protected void executeTest() {
        completesHandshakeWithUndefined = TestResults.COULD_NOT_TEST;
        if (shouldTestPointFormats) {
            supportedFormats = getSupportedPointFormats();
            completesHandshakeWithUndefined = canHandshakeWithUndefinedFormat();
        }
        tls13SecpCompression =
                shouldTestTls13 ? getTls13SecpCompressionSupported() : TestResults.COULD_NOT_TEST;
        if (supportedFormats == null) {
            LOGGER.debug("Unable to determine supported point formats");
        }
    }

    private List<ECPointFormat> getSupportedPointFormats() {
        supportedFormats = new LinkedList<>();
        testPointFormat(ECPointFormat.UNCOMPRESSED, supportedFormats);
        testPointFormat(ECPointFormat.ANSIX962_COMPRESSED_PRIME, supportedFormats);
        testPointFormat(ECPointFormat.ANSIX962_COMPRESSED_CHAR2, supportedFormats);
        return supportedFormats;
    }

    private TestResult canHandshakeWithUndefinedFormat() {
        ECPointFormat dummyFormat = ECPointFormat.UNCOMPRESSED;
        List<CipherSuite> ourECDHCipherSuites =
                ECPointFormatUtils.getCipherSuitesForTest(clientAdvertisedCipherSuites);
        Config baseConfig = scannerConfig.createConfig();

        List<NamedGroup> groups = ECPointFormatUtils.getGroupsForTest(dummyFormat, baseConfig);
        State state =
                ECPointFormatUtils.getState(ourECDHCipherSuites, dummyFormat, groups, baseConfig);
        ECPointFormatExtensionMessage modifiedExtension = new ECPointFormatExtensionMessage();
        modifiedExtension.setPointFormats(Modifiable.explicit(ECPointFormatUtils.UNDEFINED_FORMAT));
        List<ExtensionMessage> extensionList = new LinkedList<>();
        extensionList.add(modifiedExtension);
        if (shouldAddRenegotiationInfo) {
            extensionList.add(new RenegotiationInfoExtensionMessage());
        }
        ServerHelloMessage serverHello =
                (ServerHelloMessage)
                        (WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO));
        serverHello.setExtensions(extensionList);
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.FINISHED)) {
            return TestResults.TRUE;
        }
        return TestResults.FALSE;
    }

    private TestResult getTls13SecpCompressionSupported() {
        try {
            // SECP curves in TLS 1.3 don't use compression, some
            // implementations
            // might still accept compression
            List<NamedGroup> secpGroups = ECPointFormatUtils.getSpecificGroups("SECP");
            Config tlsConfig = scannerConfig.createConfig();
            tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
            tlsConfig.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS13);
            tlsConfig.setDefaultServerSupportedCipherSuites(
                    CipherSuite.getImplemented().stream()
                            .filter(suite -> !suite.isTls13())
                            .collect(Collectors.toList()));
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
            tlsConfig.setDefaultServerNamedGroups(secpGroups);
            tlsConfig.setDefaultServerSupportedPointFormats(
                    ECPointFormat.ANSIX962_COMPRESSED_PRIME);
            tlsConfig.setDefaultSelectedPointFormat(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
            State state = new State(tlsConfig);

            executeState(state);
            if (WorkflowTraceResultUtil.didReceiveMessage(
                    state.getWorkflowTrace(), HandshakeMessageType.FINISHED)) {
                return TestResults.TRUE;
            }
            return TestResults.FALSE;
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not test for Tls13SecpCompression", e);
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private void testPointFormat(ECPointFormat format, List<ECPointFormat> supportedFormats) {
        List<CipherSuite> ourECDHCipherSuites =
                ECPointFormatUtils.getCipherSuitesForTest(clientAdvertisedCipherSuites);

        List<NamedGroup> groups =
                ECPointFormatUtils.getGroupsForTest(format, scannerConfig.createConfig());
        State state =
                ECPointFormatUtils.getState(
                        ourECDHCipherSuites, format, groups, scannerConfig.createConfig());
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.FINISHED)) {
            supportedFormats.add(format);
        }
    }

    @Override
    public void adjustConfig(ClientReport report) {
        shouldTestPointFormats = ECPointFormatUtils.testInPreTLS13(report);
        shouldTestTls13 = ECPointFormatUtils.testInPreTLS13(report);
        shouldAddRenegotiationInfo =
                report.getClientAdvertisedExtensions().contains(ExtensionType.RENEGOTIATION_INFO)
                        || report.getClientAdvertisedCipherSuites()
                                .contains(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        clientAdvertisedCipherSuites.addAll(report.getClientAdvertisedCipherSuites());
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return ECPointFormatUtils.getRequirements();
    }
}
