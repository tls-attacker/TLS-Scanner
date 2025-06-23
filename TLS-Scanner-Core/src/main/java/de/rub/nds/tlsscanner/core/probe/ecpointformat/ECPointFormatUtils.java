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

    /**
     * Retrieves all cipher suites that support ECDH key exchange.
     *
     * @return A list of cipher suites containing "TLS_ECDH" in their name
     */
    public static List<CipherSuite> getCipherSuitesForTest() {
        List<CipherSuite> ourECDHCipherSuites = new LinkedList<>();
        for (CipherSuite cipherSuite : CipherSuite.values()) {
            if (cipherSuite.name().contains("TLS_ECDH")) {
                ourECDHCipherSuites.add(cipherSuite);
            }
        }
        return ourECDHCipherSuites;
    }

    /**
     * Filters the peer's supported cipher suites to include only those that support ECDH key
     * exchange.
     *
     * @param peerSupported The list of cipher suites supported by the peer
     * @return A filtered list containing only cipher suites with "TLS_ECDH" in their name
     */
    public static List<CipherSuite> getCipherSuitesForTest(List<CipherSuite> peerSupported) {
        List<CipherSuite> ourECDHCipherSuites = new LinkedList<>();
        for (CipherSuite cipherSuite : peerSupported) {
            if (cipherSuite.name().contains("TLS_ECDH")) {
                ourECDHCipherSuites.add(cipherSuite);
            }
        }
        return ourECDHCipherSuites;
    }

    /**
     * Retrieves the appropriate named groups for testing based on the specified EC point format.
     *
     * @param format The EC point format to get groups for
     * @param baseConfig The base configuration containing default client named groups
     * @return A list of named groups suitable for the specified format, or null if format is not
     *     supported
     */
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

    /**
     * Creates and configures a TLS state for EC point format testing.
     *
     * @param ourECDHCipherSuites The list of ECDH cipher suites to use
     * @param format The EC point format to configure
     * @param groups The named groups to use
     * @param baseConfig The base configuration to modify
     * @return A configured State object ready for EC point format testing
     */
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

    /**
     * Retrieves named groups that contain a specific identifier in their name.
     *
     * @param identifier The string to search for in group names (e.g., "SECP" or "SECT")
     * @return A list of named groups whose names contain the specified identifier
     */
    public static List<NamedGroup> getSpecificGroups(String identifier) {
        List<NamedGroup> secpGroups = new LinkedList<>();
        for (NamedGroup group : NamedGroup.getImplemented()) {
            if (group.name().contains(identifier)) {
                secpGroups.add(group);
            }
        }
        return secpGroups;
    }

    /**
     * Creates requirements for EC point format testing.
     *
     * @param <ReportT> The type of scan report that extends TlsScanReport
     * @return A Requirement object specifying that ECDHE support or TLS 1.3 support is needed
     */
    public static <ReportT extends TlsScanReport> Requirement<ReportT> getRequirements() {
        return new ProbeRequirement<ReportT>(
                        TlsProbeType.PROTOCOL_VERSION, TlsProbeType.CIPHER_SUITE)
                .and(
                        new PropertyTrueRequirement<ReportT>(TlsAnalyzedProperty.SUPPORTS_ECDHE)
                                .or(
                                        new PropertyTrueRequirement<>(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3)));
    }

    /**
     * Checks if the target supports any pre-TLS 1.3 protocol versions.
     *
     * @param report The scan report to check
     * @return true if the target supports any of DTLS 1.0, DTLS 1.2, TLS 1.0, TLS 1.1, or TLS 1.2
     */
    public static boolean testInPreTLS13(TlsScanReport report) {
        return report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0) == TestResults.TRUE
                || report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2) == TestResults.TRUE
                || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2) == TestResults.TRUE
                || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1) == TestResults.TRUE
                || report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0) == TestResults.TRUE;
    }

    /**
     * Checks if the target supports TLS 1.3.
     *
     * @param report The scan report to check
     * @return true if the target supports TLS 1.3, false otherwise
     */
    public static boolean testInTLS13(TlsScanReport report) {
        return report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3) == TestResults.TRUE;
    }

    /**
     * Merges EC point format test results into the calling probe.
     *
     * @param supportedFormats The list of supported EC point formats discovered
     * @param callingProbe The probe to merge results into
     * @param completesHandshakeWithUndefined Test result for handshake with undefined point format
     * @param tls13SecpCompression Test result for TLS 1.3 SECP compression support (can be null)
     */
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
