/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.ecpointformat;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.LinkedList;
import java.util.List;

public abstract class ECPointFormatUtils {
    public static final byte[] UNDEFINED_FORMAT = new byte[] {(byte) 0xE4, (byte) 0x04};

    private ECPointFormatUtils() {}

    public static List<CipherSuite> getCipherSuitesForTest() {
        List<CipherSuite> ourECDHCipherSuites = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.name().contains("TLS_ECDH")) {
                ourECDHCipherSuites.add(cipherSuite);
            }
        }
        return ourECDHCipherSuites;
    }

    public static List<CipherSuite> getCipherSuitesForTest(List<CipherSuite> peerSupported) {
        List<CipherSuite> ourECDHCipherSuites = new LinkedList<>();
        for (CipherSuite cipherSuite : peerSupported) {
            if (cipherSuite.name().contains("TLS_ECDH")) {
                ourECDHCipherSuites.add(cipherSuite);
            }
        }
        return ourECDHCipherSuites;
    }

    public static List<NamedGroup> getGroupsForTest(ECPointFormat format, Config baseConfig) {
        List<NamedGroup> groups = null;
        switch (format) {
            case UNCOMPRESSED:
                groups = new LinkedList<>();
                groups.addAll(baseConfig.getDefaultClientNamedGroups());
                groups.remove(NamedGroup.ECDH_X25519);
                groups.remove(NamedGroup.ECDH_X448);
                break;
            case ANSIX962_COMPRESSED_PRIME:
                groups = getSpecificGroups("SECP");
                break;
            case ANSIX962_COMPRESSED_CHAR2:
                groups = getSpecificGroups("SECT");
                break;
        }
        return groups;
    }

    public static State getState(
            List<CipherSuite> ourECDHCipherSuites,
            ECPointFormat format,
            List<NamedGroup> groups,
            Config baseConfig) {
        baseConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
        baseConfig.setDefaultClientSupportedCipherSuites(ourECDHCipherSuites);
        baseConfig.setDefaultServerSupportedCipherSuites(ourECDHCipherSuites);
        baseConfig.setDefaultSelectedCipherSuite(ourECDHCipherSuites.get(0));
        baseConfig.setDefaultClientNamedGroups(groups);
        baseConfig.setDefaultSelectedPointFormat(format);
        baseConfig.setDefaultServerSupportedPointFormats(format);
        baseConfig.setDefaultClientSupportedPointFormats(format);
        baseConfig.setEnforceSettings(true);

        State state = new State(baseConfig);
        return state;
    }

    public static List<NamedGroup> getSpecificGroups(String identifier) {
        List<NamedGroup> secpGroups = new LinkedList<>();
        for (NamedGroup group : NamedGroup.getImplemented()) {
            if (group.name().contains(identifier)) {
                secpGroups.add(group);
            }
        }
        return secpGroups;
    }

    public static <ReportT extends TlsScanReport> Requirement<ReportT> getRequirements() {
        return new ProbeRequirement<ReportT>(
                        TlsProbeType.PROTOCOL_VERSION, TlsProbeType.CIPHER_SUITE)
                .and(
                        new PropertyTrueRequirement<ReportT>(TlsAnalyzedProperty.SUPPORTS_ECDHE)
                                .or(
                                        new PropertyTrueRequirement<>(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3)));
    }

    public static boolean testInPreTLS13(TlsScanReport report) {
        return report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0) == TestResults.TRUE
                || report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2) == TestResults.TRUE
                || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2) == TestResults.TRUE
                || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1) == TestResults.TRUE
                || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0) == TestResults.TRUE;
    }

    public static boolean testInTLS13(TlsScanReport report) {
        return report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3) == TestResults.TRUE;
    }

    public static void mergeInProbe(
            List<ECPointFormat> supportedFormats,
            TlsProbe<?> callingProbe,
            TestResult completesHandshakeWithUndefined,
            TestResult tls13SecpCompression) {
        TestResult supportsUncompressedPoint = TestResults.FALSE;
        TestResult supportsANSIX962CompressedPrime = TestResults.FALSE;
        TestResult supportsANSIX962CompressedChar2 = TestResults.FALSE;
        if (supportedFormats != null) {
            for (ECPointFormat format : supportedFormats) {
                switch (format) {
                    case UNCOMPRESSED:
                        supportsUncompressedPoint = TestResults.TRUE;
                        break;
                    case ANSIX962_COMPRESSED_PRIME:
                        supportsANSIX962CompressedPrime = TestResults.TRUE;
                        break;
                    case ANSIX962_COMPRESSED_CHAR2:
                        supportsANSIX962CompressedChar2 = TestResults.TRUE;
                        break;
                    default:
                        ; // will never occur as all enum types are caught
                }
            }
        }
        callingProbe.put(
                TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, supportsUncompressedPoint);
        callingProbe.put(
                TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME,
                supportsANSIX962CompressedPrime);
        callingProbe.put(
                TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2,
                supportsANSIX962CompressedChar2);
        callingProbe.put(
                TlsAnalyzedProperty.HANDSHAKES_WITH_UNDEFINED_POINT_FORMAT,
                completesHandshakeWithUndefined);
        if (tls13SecpCompression != null) {
            callingProbe.put(
                    TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION, tls13SecpCompression);
        } else {
            callingProbe.put(
                    TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION,
                    TestResults.COULD_NOT_TEST);
        }
    }
}
