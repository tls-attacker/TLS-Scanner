/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.result.ECPointFormatResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class ECPointFormatProbe extends TlsProbe<ServerScannerConfig, ServerReport, ECPointFormatResult> {
    private static final byte[] UNDEFINED_FORMAT = new byte[] { (byte) 0xE4, (byte) 0x04 };

    private Boolean shouldTestTls13;
    private Boolean shouldTestPointFormats;

    public ECPointFormatProbe(ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.EC_POINT_FORMAT, scannerConfig);
    }

    @Override
    public ECPointFormatResult executeTest() {
        List<ECPointFormat> pointFormats = null;
        TestResult completedWithUndefined = TestResults.CANNOT_BE_TESTED;
        if (shouldTestPointFormats) {
            pointFormats = getSupportedPointFormats();
            completedWithUndefined = canHandshakeWithUndefinedFormat();
        }
        TestResult tls13SecpCompressionSupported;
        if (shouldTestTls13) {
            tls13SecpCompressionSupported = getTls13SecpCompressionSupported();
        } else {
            tls13SecpCompressionSupported = TestResults.COULD_NOT_TEST;
        }
        if (pointFormats != null) {
            return (new ECPointFormatResult(pointFormats, tls13SecpCompressionSupported, completedWithUndefined));

        } else {
            LOGGER.debug("Unable to determine supported point formats");
            return (new ECPointFormatResult(null, tls13SecpCompressionSupported, completedWithUndefined));
        }
    }

    private List<ECPointFormat> getSupportedPointFormats() {
        List<ECPointFormat> supportedFormats = new LinkedList<>();
        testPointFormat(ECPointFormat.UNCOMPRESSED, supportedFormats);
        testPointFormat(ECPointFormat.ANSIX962_COMPRESSED_PRIME, supportedFormats);
        testPointFormat(ECPointFormat.ANSIX962_COMPRESSED_CHAR2, supportedFormats);
        return supportedFormats;
    }

    private TestResult canHandshakeWithUndefinedFormat() {
        ECPointFormat dummyFormat = ECPointFormat.UNCOMPRESSED;
        List<CipherSuite> ourECDHCipherSuites = getCipherSuitesForTest();
        List<NamedGroup> groups = getGroupsForTest(dummyFormat);
        State state = getState(ourECDHCipherSuites, dummyFormat, groups);
        state.getWorkflowTrace().getFirstSendMessage(ClientHelloMessage.class)
            .getExtension(ECPointFormatExtensionMessage.class).setPointFormats(Modifiable.explicit(UNDEFINED_FORMAT));
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        }
        return TestResults.FALSE;
    }

    private void testPointFormat(ECPointFormat format, List<ECPointFormat> supportedFormats) {
        List<CipherSuite> ourECDHCipherSuites = getCipherSuitesForTest();

        List<NamedGroup> groups = getGroupsForTest(format);
        State state = getState(ourECDHCipherSuites, format, groups);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            supportedFormats.add(format);
        }
    }

    public List<CipherSuite> getCipherSuitesForTest() {
        List<CipherSuite> ourECDHCipherSuites = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.name().contains("TLS_ECDH")) {
                ourECDHCipherSuites.add(cipherSuite);
            }
        }
        return ourECDHCipherSuites;
    }

    public List<NamedGroup> getGroupsForTest(ECPointFormat format) {
        List<NamedGroup> groups = null;
        switch (format) {
            case UNCOMPRESSED:
                groups = new LinkedList<>();
                groups.addAll(Arrays.asList(NamedGroup.values()));
                groups.remove(NamedGroup.ECDH_X25519);
                groups.remove(NamedGroup.ECDH_X448);
                break;
            case ANSIX962_COMPRESSED_PRIME:
                groups = getSecpGroups();
                break;
            case ANSIX962_COMPRESSED_CHAR2:
                groups = getSectGroups();
                break;
            default: // will never occur as all enum types are caught
                ;
        }
        return groups;
    }

    public State getState(List<CipherSuite> ourECDHCipherSuites, ECPointFormat format, List<NamedGroup> groups) {
        Config config = getScannerConfig().createConfig();
        config.setDefaultClientSupportedCipherSuites(ourECDHCipherSuites);
        config.setDefaultSelectedCipherSuite(ourECDHCipherSuites.get(0));
        config.setEnforceSettings(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddECPointFormatExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddRenegotiationInfoExtension(true);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
        config.setQuickReceive(true);
        config.setDefaultSelectedPointFormat(format);
        config.setEarlyStop(true);
        config.setStopActionsAfterIOException(true);
        config.setStopActionsAfterFatal(true);
        config.setStopReceivingAfterFatal(true);
        config.setDefaultClientNamedGroups(groups);
        State state = new State(config);
        return state;
    }

    private TestResult getTls13SecpCompressionSupported() {
        try {
            // SECP curves in TLS 1.3 don't use compression, some
            // implementations
            // might still accept compression
            List<NamedGroup> secpGroups = getSecpGroups();
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
            tlsConfig.setDefaultClientNamedGroups(secpGroups);
            tlsConfig.setDefaultClientKeyShareNamedGroups(secpGroups);
            tlsConfig.setAddECPointFormatExtension(false);
            tlsConfig.setAddEllipticCurveExtension(true);
            tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
            tlsConfig.setAddSupportedVersionsExtension(true);
            tlsConfig.setAddKeyShareExtension(true);
            tlsConfig.setAddCertificateStatusRequestExtension(true);
            tlsConfig.setUseFreshRandom(true);
            tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(
                SignatureAndHashAlgorithm.getImplementedTls13SignatureAndHashAlgorithms());
            tlsConfig.setDefaultClientSupportedPointFormats(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
            tlsConfig.setDefaultSelectedPointFormat(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
            State state = new State(tlsConfig);

            executeState(state);
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
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

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return report.isProbeAlreadyExecuted(TlsProbeType.PROTOCOL_VERSION)
            && (report.getResult(TlsAnalyzedProperty.SUPPORTS_ECDHE) == TestResults.TRUE
                || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3) == TestResults.TRUE);
    }

    @Override
    public ECPointFormatResult getCouldNotExecuteResult() {
        return new ECPointFormatResult(null, TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST);

    }

    @Override
    public void adjustConfig(ServerReport report) {
        shouldTestPointFormats = report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0) == TestResults.TRUE
            || report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2) == TestResults.TRUE
            || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2) == TestResults.TRUE
            || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1) == TestResults.TRUE
            || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0) == TestResults.TRUE;
        shouldTestTls13 = report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3) == TestResults.TRUE;
    }

    private List<NamedGroup> getSecpGroups() {
        List<NamedGroup> secpGroups = new LinkedList<>();
        for (NamedGroup group : NamedGroup.getImplemented()) {
            if (group.name().contains("SECP")) {
                secpGroups.add(group);
            }
        }

        return secpGroups;
    }

    private List<NamedGroup> getSectGroups() {
        List<NamedGroup> sectGroups = new LinkedList<>();
        for (NamedGroup group : NamedGroup.getImplemented()) {
            if (group.name().contains("SECT")) {
                sectGroups.add(group);
            }
        }

        return sectGroups;
    }

}
