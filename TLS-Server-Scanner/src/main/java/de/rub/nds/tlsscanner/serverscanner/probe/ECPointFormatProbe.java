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
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
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
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ECPointFormatResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class ECPointFormatProbe extends TlsProbe {

    private Boolean shouldTestTls13;
    private Boolean shouldTestPointFormats;

    public ECPointFormatProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.EC_POINT_FORMAT, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<ECPointFormat> pointFormats = null;
            if (shouldTestPointFormats) {
                pointFormats = getSupportedPointFormats();
            }
            TestResult tls13SecpCompressionSupported;
            if (shouldTestTls13) {
                tls13SecpCompressionSupported = getTls13SecpCompressionSupported();
            } else {
                tls13SecpCompressionSupported = TestResult.COULD_NOT_TEST;
            }
            if (pointFormats != null) {
                return (new ECPointFormatResult(pointFormats, tls13SecpCompressionSupported));

            } else {
                LOGGER.debug("Unable to determine supported point formats");
                return (new ECPointFormatResult(null, tls13SecpCompressionSupported));
            }
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new ECPointFormatResult(null, TestResult.ERROR_DURING_TEST);
        }
    }

    private List<ECPointFormat> getSupportedPointFormats() {
        List<ECPointFormat> supportedFormats = new LinkedList<>();
        testPointFormat(ECPointFormat.UNCOMPRESSED, supportedFormats);
        testPointFormat(ECPointFormat.ANSIX962_COMPRESSED_PRIME, supportedFormats);
        testPointFormat(ECPointFormat.ANSIX962_COMPRESSED_CHAR2, supportedFormats);
        return supportedFormats;
    }

    private void testPointFormat(ECPointFormat format, List<ECPointFormat> supportedFormats) {
        List<CipherSuite> ourECDHCipherSuites = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.name().contains("TLS_ECDH")) {
                ourECDHCipherSuites.add(cipherSuite);
            }
        }

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
        Config config = getScannerConfig().createConfig();
        config.setDefaultClientSupportedCipherSuites(ourECDHCipherSuites);
        config.setDefaultSelectedCipherSuite(ourECDHCipherSuites.get(0));
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        config.setEnforceSettings(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddECPointFormatExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddRenegotiationInfoExtension(true);
        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        config.setQuickReceive(true);
        config.setDefaultSelectedPointFormat(format);
        config.setEarlyStop(true);
        config.setStopActionsAfterFatal(true);
        config.setDefaultClientNamedGroups(groups);
        State state = new State(config);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            supportedFormats.add(format);
        }
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
                return TestResult.TRUE;
            }
            return TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not test for Tls13SecpCompression", e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION)
            && (report.getResult(AnalyzedProperty.SUPPORTS_ECDH) == TestResult.TRUE
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.TRUE);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new ECPointFormatResult(null, TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        shouldTestPointFormats = report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.TRUE
            || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.TRUE
            || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.TRUE;
        shouldTestTls13 = report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.TRUE;
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
