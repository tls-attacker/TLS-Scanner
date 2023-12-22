/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceConfigurationUtil;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.ecpointformat.ECPointFormatUtils;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.LinkedList;
import java.util.List;

public class ECPointFormatProbe extends TlsServerProbe {

    private Boolean shouldTestTls13;
    private Boolean shouldTestPointFormats;

    private TestResult completesHandshakeWithUndefined = TestResults.FALSE;

    private List<ECPointFormat> supportedFormats;
    private TestResult tls13SecpCompression;

    public ECPointFormatProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.EC_POINT_FORMAT, configSelector);
        register(
                TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT,
                TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME,
                TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2,
                TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION,
                TlsAnalyzedProperty.HANDSHAKES_WITH_UNDEFINED_POINT_FORMAT);
    }

    @Override
    protected void executeTest() {
        completesHandshakeWithUndefined = TestResults.CANNOT_BE_TESTED;
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
        List<CipherSuite> ourECDHCipherSuites = ECPointFormatUtils.getCipherSuitesForTest();
        List<NamedGroup> groups =
                ECPointFormatUtils.getGroupsForTest(dummyFormat, configSelector.getBaseConfig());
        State state =
                ECPointFormatUtils.getState(
                        ourECDHCipherSuites, dummyFormat, groups, configSelector.getBaseConfig());
        ClientHelloMessage clientHelloMessage =
                (ClientHelloMessage)
                        (WorkflowTraceConfigurationUtil.getFirstStaticConfiguredSendMessage(
                                state.getWorkflowTrace(), HandshakeMessageType.CLIENT_HELLO));
        clientHelloMessage
                .getExtension(ECPointFormatExtensionMessage.class)
                .setPointFormats(Modifiable.explicit(ECPointFormatUtils.UNDEFINED_FORMAT));
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.FINISHED)) {
            return TestResults.TRUE;
        }
        return TestResults.FALSE;
    }

    private void testPointFormat(ECPointFormat format, List<ECPointFormat> supportedFormats) {
        List<CipherSuite> ourECDHCipherSuites = ECPointFormatUtils.getCipherSuitesForTest();

        List<NamedGroup> groups =
                ECPointFormatUtils.getGroupsForTest(format, configSelector.getBaseConfig());
        State state =
                ECPointFormatUtils.getState(
                        ourECDHCipherSuites, format, groups, configSelector.getBaseConfig());
        executeState(state);
        if (WorkflowTraceResultUtil.didReceiveMessage(
                state.getWorkflowTrace(), HandshakeMessageType.FINISHED)) {
            supportedFormats.add(format);
        }
    }

    private TestResult getTls13SecpCompressionSupported() {
        try {
            // SECP curves in TLS 1.3 don't use compression, some
            // implementations
            // might still accept compression
            List<NamedGroup> secpGroups = ECPointFormatUtils.getSpecificGroups("SECP");
            Config tlsConfig = configSelector.getTls13BaseConfig();
            tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
            tlsConfig.setDefaultClientNamedGroups(secpGroups);
            tlsConfig.setDefaultClientKeyShareNamedGroups(secpGroups);
            tlsConfig.setDefaultClientSupportedPointFormats(
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

    @Override
    public Requirement<ServerReport> getRequirements() {
        return ECPointFormatUtils.getRequirements();
    }

    @Override
    public void adjustConfig(ServerReport report) {
        shouldTestPointFormats = ECPointFormatUtils.testInPreTLS13(report);
        shouldTestTls13 = ECPointFormatUtils.testInPreTLS13(report);
    }

    @Override
    protected void mergeData(ServerReport report) {
        ECPointFormatUtils.mergeInProbe(
                supportedFormats, this, completesHandshakeWithUndefined, tls13SecpCompression);
    }
}
