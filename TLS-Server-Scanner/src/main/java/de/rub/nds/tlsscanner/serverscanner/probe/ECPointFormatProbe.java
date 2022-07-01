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
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.OrRequirement;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.core.probe.requirements.PropertyRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;
import java.util.List;

public class ECPointFormatProbe extends TlsServerProbe<ConfigSelector, ServerReport> {
    private static final byte[] UNDEFINED_FORMAT = new byte[] { (byte) 0xE4, (byte) 0x04 };

    private Boolean shouldTestTls13;
    private Boolean shouldTestPointFormats;

    private TestResult supportsUncompressedPoint = TestResults.FALSE;
    private TestResult supportsANSIX962CompressedPrime = TestResults.FALSE;
    private TestResult supportsANSIX962CompressedChar2 = TestResults.FALSE;
    private TestResult completesHandshakeWithUndefined = TestResults.FALSE;

    private List<ECPointFormat> supportedFormats;
    private TestResult tls13SecpCompression;

    public ECPointFormatProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.EC_POINT_FORMAT, configSelector);
        register(TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT,
            TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME,
            TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION,
            TlsAnalyzedProperty.HANDSHAKES_WITH_UNDEFINED_POINT_FORMAT);
    }

    @Override
    public void executeTest() {
        completesHandshakeWithUndefined = TestResults.CANNOT_BE_TESTED;
        if (shouldTestPointFormats) {
            supportedFormats = getSupportedPointFormats();
            completesHandshakeWithUndefined = canHandshakeWithUndefinedFormat();
        }
        tls13SecpCompression = shouldTestTls13 ? getTls13SecpCompressionSupported() : TestResults.COULD_NOT_TEST;
        if (supportedFormats == null) {
            LOGGER.debug("Unable to determine supported point formats");
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
                groups.addAll(configSelector.getBaseConfig().getDefaultClientNamedGroups());
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

    public State getState(List<CipherSuite> ourECDHCipherSuites, ECPointFormat format, List<NamedGroup> groups) {
        Config config = configSelector.getBaseConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
        config.setDefaultClientSupportedCipherSuites(ourECDHCipherSuites);
        config.setDefaultSelectedCipherSuite(ourECDHCipherSuites.get(0));
        config.setDefaultClientNamedGroups(groups);
        configSelector.repairConfig(config);
        config.setDefaultSelectedPointFormat(format);
        config.setEnforceSettings(true);

        State state = new State(config);
        return state;
    }

    private TestResult getTls13SecpCompressionSupported() {
        try {
            // SECP curves in TLS 1.3 don't use compression, some
            // implementations
            // might still accept compression
            List<NamedGroup> secpGroups = getSpecificGroups("SECP");
            Config tlsConfig = configSelector.getTls13BaseConfig();
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
            tlsConfig.setDefaultClientNamedGroups(secpGroups);
            tlsConfig.setDefaultClientKeyShareNamedGroups(secpGroups);
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
    protected Requirement getRequirements() {
        PropertyRequirement preq_ecdh = new PropertyRequirement(TlsAnalyzedProperty.SUPPORTS_ECDHE);
        PropertyRequirement preq_tls13 = new PropertyRequirement(TlsAnalyzedProperty.SUPPORTS_TLS_1_3);
        return new ProbeRequirement(TlsProbeType.PROTOCOL_VERSION, TlsProbeType.CIPHER_SUITE)
            .requires(new OrRequirement(preq_ecdh, preq_tls13));
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

    private List<NamedGroup> getSpecificGroups(String identifier) {
        List<NamedGroup> secpGroups = new LinkedList<>();
        for (NamedGroup group : configSelector.getBaseConfig().getDefaultClientNamedGroups()) {
            if (group.name().contains(identifier)) {
                secpGroups.add(group);
            }
        }
        return secpGroups;
    }

    @Override
    protected void mergeData(ServerReport report) {
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
        } else {
            supportsUncompressedPoint = TestResults.COULD_NOT_TEST;
            supportsANSIX962CompressedPrime = TestResults.COULD_NOT_TEST;
            supportsANSIX962CompressedChar2 = TestResults.COULD_NOT_TEST;
        }
        put(TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, supportsUncompressedPoint);
        put(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME, supportsANSIX962CompressedPrime);
        put(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, supportsANSIX962CompressedChar2);
        put(TlsAnalyzedProperty.HANDSHAKES_WITH_UNDEFINED_POINT_FORMAT, completesHandshakeWithUndefined);
        if (tls13SecpCompression != null) {
            put(TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION, tls13SecpCompression);
        } else {
            put(TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION, TestResults.COULD_NOT_TEST);
        }
    }
}
