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
import de.rub.nds.scanner.core.probe.requirements.FulfilledRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlpnProtocol;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.ClientHelloPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class CommonBugProbe extends TlsServerProbe {

    // does it handle unknown extensions correctly?
    private TestResult extensionIntolerance = TestResults.COULD_NOT_TEST;
    // does it handle unknown cipher suites correctly?
    private TestResult cipherSuiteIntolerance = TestResults.COULD_NOT_TEST;
    // does it handle long cipher suite length values correctly?
    private TestResult cipherSuiteLengthIntolerance512 = TestResults.COULD_NOT_TEST;
    // does it handle unknown compression algorithms correctly?
    private TestResult compressionIntolerance = TestResults.COULD_NOT_TEST;
    // does it handle unknown versions correctly?
    private TestResult versionIntolerance = TestResults.COULD_NOT_TEST;
    // does it handle unknown alpn strings correctly?
    private TestResult alpnIntolerance = TestResults.COULD_NOT_TEST;
    // 256 - 511 <-- ch should be bigger than this?
    private TestResult clientHelloLengthIntolerance = TestResults.COULD_NOT_TEST;
    // does it break on empty last extension?
    private TestResult emptyLastExtensionIntolerance = TestResults.COULD_NOT_TEST;
    // is only the second byte of the cipher suite evaluated?
    private TestResult onlySecondCipherSuiteByteEvaluated = TestResults.COULD_NOT_TEST;
    // does it handle unknown groups correctly?
    private TestResult namedGroupIntolerant = TestResults.COULD_NOT_TEST;
    // does it handle signature and hash algorithms correctly?
    private TestResult namedSignatureAndHashAlgorithmIntolerance = TestResults.COULD_NOT_TEST;
    // does it ignore the offered cipher suites?
    private TestResult ignoresCipherSuiteOffering = TestResults.COULD_NOT_TEST;
    // does it reflect the offered cipher suites?
    private TestResult reflectsCipherSuiteOffering = TestResults.COULD_NOT_TEST;
    // does it ignore the offered named groups?
    private TestResult ignoresOfferedNamedGroups = TestResults.COULD_NOT_TEST;
    // does it ignore the sig hash algorithms?
    private TestResult ignoresOfferedSignatureAndHashAlgorithms = TestResults.COULD_NOT_TEST;
    // server does not like really big client hello messages
    private TestResult maxLengthClientHelloIntolerant = TestResults.COULD_NOT_TEST;
    // does it accept grease values in the supported groups extension?
    private TestResult greaseNamedGroupIntolerance = TestResults.COULD_NOT_TEST;
    // does it accept grease values in the cipher suites list?
    private TestResult greaseCipherSuiteIntolerance = TestResults.COULD_NOT_TEST;
    // does it accept grease values in the signature and hash algorithms extension?
    private TestResult greaseSignatureAndHashAlgorithmIntolerance = TestResults.COULD_NOT_TEST;

    public CommonBugProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.COMMON_BUGS, configSelector);
        register(
                TlsAnalyzedProperty.HAS_EXTENSION_INTOLERANCE,
                TlsAnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE,
                TlsAnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE,
                TlsAnalyzedProperty.HAS_COMPRESSION_INTOLERANCE,
                TlsAnalyzedProperty.HAS_VERSION_INTOLERANCE,
                TlsAnalyzedProperty.HAS_ALPN_INTOLERANCE,
                TlsAnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE,
                TlsAnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE,
                TlsAnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG,
                TlsAnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE,
                TlsAnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE,
                TlsAnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES,
                TlsAnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES,
                TlsAnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS,
                TlsAnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS,
                TlsAnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE,
                TlsAnalyzedProperty.HAS_GREASE_NAMED_GROUP_INTOLERANCE,
                TlsAnalyzedProperty.HAS_GREASE_CIPHER_SUITE_INTOLERANCE,
                TlsAnalyzedProperty.HAS_GREASE_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE);
    }

    @Override
    protected void executeTest() {
        extensionIntolerance = hasExtensionIntolerance();
        cipherSuiteIntolerance = hasCipherSuiteIntolerance();
        cipherSuiteLengthIntolerance512 = hasCipherSuiteLengthIntolerance512();
        compressionIntolerance = hasCompressionIntolerance();
        versionIntolerance = hasVersionIntolerance();
        alpnIntolerance = hasAlpnIntolerance();
        clientHelloLengthIntolerance = hasClientHelloLengthIntolerance();
        emptyLastExtensionIntolerance = hasEmptyLastExtensionIntolerance();
        onlySecondCipherSuiteByteEvaluated = hasOnlySecondCipherSuiteByteEvaluatedBug();
        namedGroupIntolerant = hasNamedGroupIntolerance();
        namedSignatureAndHashAlgorithmIntolerance = hasSignatureAndHashAlgorithmIntolerance();
        adjustCipherSuiteSelectionBugs();
        ignoresOfferedNamedGroups = hasIgnoresNamedGroupsOfferingBug();
        ignoresOfferedSignatureAndHashAlgorithms = hasIgnoresSigHashAlgoOfferingBug();
        maxLengthClientHelloIntolerant = hasBigClientHelloIntolerance();
        greaseNamedGroupIntolerance = hasGreaseNamedGroupIntolerance();
        greaseCipherSuiteIntolerance = hasGreaseCipherSuiteIntolerance();
        greaseSignatureAndHashAlgorithmIntolerance =
                hasGreaseSignatureAndHashAlgorithmIntolerance();
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new FulfilledRequirement<>();
    }

    private int getClientHelloLength(ClientHelloMessage message, Config config) {
        Chooser chooser =
                ChooserFactory.getChooser(
                        ChooserType.DEFAULT,
                        new Context(new State(config), config.getDefaultClientConnection()),
                        config);
        ClientHelloPreparator preparator = new ClientHelloPreparator(chooser, message);
        preparator.prepare();
        ClientHelloSerializer serializer =
                new ClientHelloSerializer(message, config.getDefaultHighestClientProtocolVersion());
        return serializer.serialize().length;
    }

    private WorkflowTrace getWorkflowTrace(Config config, ClientHelloMessage clientHello) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(clientHello));
        if (config.getHighestProtocolVersion().isDTLS() && config.isDtlsCookieExchange()) {
            trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
            trace.addTlsAction(new SendAction(clientHello));
        }
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        return trace;
    }

    private TestResult getResult(Config config, WorkflowTrace trace, boolean checkForTrue) {
        try {
            State state = new State(config, trace);
            executeState(state);
            return checkForTrue
                            == (WorkflowTraceResultUtil.didReceiveMessage(
                                            trace, HandshakeMessageType.SERVER_HELLO_DONE)
                                    || (state.getTlsContext().getSelectedProtocolVersion()
                                                    == ProtocolVersion.TLS13
                                            && (WorkflowTraceResultUtil.didReceiveMessage(
                                                    trace, HandshakeMessageType.FINISHED))))
                    ? TestResults.TRUE
                    : TestResults.FALSE;
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not scan for " + getProbeName(), e);
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult hasExtensionIntolerance() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        ClientHelloMessage message = new ClientHelloMessage(config);
        UnknownExtensionMessage extension = new UnknownExtensionMessage();
        extension.setTypeConfig(new byte[] {(byte) 3F, (byte) 3F});
        extension.setDataConfig(new byte[] {00, 11, 22, 33});
        message.getExtensions().add(extension);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasBigClientHelloIntolerance() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        config.setAddPaddingExtension(true);
        config.setDefaultPaddingExtensionBytes(new byte[14000]);
        ClientHelloMessage message = new ClientHelloMessage(config);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasIgnoresSigHashAlgoOfferingBug() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        config.setAddSignatureAndHashAlgorithmsExtension(false);
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isEphemeral()) {
                suiteList.add(suite);
            }
        }
        config.setDefaultClientSupportedCipherSuites(suiteList);
        configSelector.repairConfig(config);
        ClientHelloMessage message = new ClientHelloMessage(config);
        SignatureAndHashAlgorithmsExtensionMessage extension =
                new SignatureAndHashAlgorithmsExtensionMessage();
        extension.setSignatureAndHashAlgorithms(
                Modifiable.explicit(new byte[] {(byte) 0xED, (byte) 0xED}));
        message.addExtension(extension);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, true);
    }

    private TestResult hasIgnoresNamedGroupsOfferingBug() {
        if (configSelector.foundWorkingConfig()) {
            Config config = configSelector.getBaseConfig();
            List<CipherSuite> suiteList = new LinkedList<>();
            for (CipherSuite suite : CipherSuite.getImplemented()) {
                if (suite.isEphemeral() && suite.name().contains("EC")) {
                    suiteList.add(suite);
                }
            }
            config.setDefaultClientSupportedCipherSuites(suiteList);
            config.setAddECPointFormatExtension(true);
            config.setAddEllipticCurveExtension(false);
            ClientHelloMessage message = new ClientHelloMessage(config);
            EllipticCurvesExtensionMessage extension = new EllipticCurvesExtensionMessage();
            extension.setSupportedGroups(
                    Modifiable.explicit(new byte[] {(byte) 0xED, (byte) 0xED}));
            message.addExtension(extension);
            WorkflowTrace trace = getWorkflowTrace(config, message);
            return getResult(config, trace, true);
        } else {
            // servers choosing a different group in TLS 1.3 would send an
            // invalid HelloRetryRequest message which has a significantly
            // different meaning than the TLS 1.2 test case
            return TestResults.FALSE;
        }
    }

    private void adjustCipherSuiteSelectionBugs() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        ClientHelloMessage message = new ClientHelloMessage(config);
        message.setCipherSuites(Modifiable.explicit(new byte[] {(byte) 0xEE, (byte) 0xCC}));
        WorkflowTrace trace = getWorkflowTrace(config, message);
        State state = new State(config, trace);
        executeState(state);
        TestResult receivedShd = getResult(config, trace, true);
        if (receivedShd == TestResults.TRUE) {
            ServerHelloMessage serverHelloMessage =
                    (ServerHelloMessage)
                            WorkflowTraceResultUtil.getFirstReceivedMessage(
                                    trace, HandshakeMessageType.SERVER_HELLO);
            if (Arrays.equals(
                    serverHelloMessage.getSelectedCipherSuite().getValue(),
                    new byte[] {(byte) 0xEE, (byte) 0xCC})) {
                reflectsCipherSuiteOffering = TestResults.TRUE;
                ignoresCipherSuiteOffering = TestResults.FALSE;
            } else {
                reflectsCipherSuiteOffering = TestResults.FALSE;
                ignoresCipherSuiteOffering = TestResults.TRUE;
            }
        } else if (receivedShd == TestResults.FALSE) {
            reflectsCipherSuiteOffering = TestResults.FALSE;
            ignoresCipherSuiteOffering = TestResults.FALSE;
        } else if (receivedShd == TestResults.ERROR_DURING_TEST) {
            reflectsCipherSuiteOffering = TestResults.ERROR_DURING_TEST;
            ignoresCipherSuiteOffering = TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult hasSignatureAndHashAlgorithmIntolerance() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        config.setAddSignatureAndHashAlgorithmsExtension(false);
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isEphemeral()) {
                suiteList.add(suite);
            }
        }
        config.setDefaultClientSupportedCipherSuites(suiteList);
        configSelector.repairConfig(config);
        ClientHelloMessage message = new ClientHelloMessage(config);
        SignatureAndHashAlgorithmsExtensionMessage extension =
                new SignatureAndHashAlgorithmsExtensionMessage();
        extension.setSignatureAndHashAlgorithms(
                Modifiable.insert(new byte[] {(byte) 0xED, (byte) 0xED}, 0));
        message.addExtension(extension);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasNamedGroupIntolerance() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isEphemeral() && suite.name().contains("EC")) {
                suiteList.add(suite);
            }
        }
        config.setDefaultClientSupportedCipherSuites(suiteList);
        config.setAddECPointFormatExtension(true);
        config.setAddEllipticCurveExtension(false);
        ClientHelloMessage message = new ClientHelloMessage(config);
        EllipticCurvesExtensionMessage extension = new EllipticCurvesExtensionMessage();
        extension.setSupportedGroups(Modifiable.insert(new byte[] {(byte) 0xED, (byte) 0xED}, 0));
        message.addExtension(extension);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasOnlySecondCipherSuiteByteEvaluatedBug() {
        if (configSelector.foundWorkingConfig()) {
            Config config = configSelector.getBaseConfig();
            ClientHelloMessage message = new ClientHelloMessage(config);
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            for (CipherSuite suite : CipherSuite.values()) {
                if (suite.getByteValue()[0] == 0x00) {
                    try {
                        stream.write(new byte[] {(byte) 0xDF, suite.getByteValue()[1]});
                    } catch (IOException ex) {
                        LOGGER.debug(ex);
                    }
                }
            }
            message.setCipherSuites(Modifiable.explicit(stream.toByteArray()));
            WorkflowTrace trace = getWorkflowTrace(config, message);
            return getResult(config, trace, true);
        } else {
            // not applicable to TLS 1.3-only servers due to 0x13XX structure
            return TestResults.FALSE;
        }
    }

    private TestResult hasEmptyLastExtensionIntolerance() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        ClientHelloMessage message = new ClientHelloMessage(config);
        ExtendedMasterSecretExtensionMessage extension = new ExtendedMasterSecretExtensionMessage();
        message.getExtensions().add(extension);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasVersionIntolerance() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        ClientHelloMessage message = new ClientHelloMessage(config);
        message.setProtocolVersion(Modifiable.explicit(new byte[] {0x03, 0x05}));
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasCompressionIntolerance() {
        if (configSelector.foundWorkingConfig()) {
            Config config = configSelector.getBaseConfig();
            ClientHelloMessage message = new ClientHelloMessage(config);
            message.setCompressions(new byte[] {(byte) 0xFF, (byte) 0x00});
            WorkflowTrace trace = getWorkflowTrace(config, message);
            return getResult(config, trace, false);
        } else {
            // At this point, we must have only found a working TLS 1.3 config
            // and RFC 8446 states:
            // If a TLS 1.3 ClientHello is received with any other value in this
            // field, the server MUST abort the handshake with an
            // "illegal_parameter" alert.
            return TestResults.FALSE;
        }
    }

    private TestResult hasCipherSuiteLengthIntolerance512() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        List<CipherSuite> toTestList = new LinkedList<>();
        toTestList.addAll(Arrays.asList(CipherSuite.values()));
        toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
        toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        config.setDefaultClientSupportedCipherSuites(toTestList);
        ClientHelloMessage message = new ClientHelloMessage(config);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasCipherSuiteIntolerance() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        ClientHelloMessage message = new ClientHelloMessage(config);
        message.setCipherSuites(Modifiable.insert(new byte[] {(byte) 0xCF, (byte) 0xAA}, 1));
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasAlpnIntolerance() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        config.setAddAlpnExtension(true);
        List<String> alpnProtocols = new LinkedList<>();
        for (AlpnProtocol protocol : AlpnProtocol.values()) {
            alpnProtocols.add(protocol.getConstant());
        }
        alpnProtocols.add("This is not an ALPN Protocol");
        config.setDefaultProposedAlpnProtocols(alpnProtocols);
        ClientHelloMessage message = new ClientHelloMessage(config);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasClientHelloLengthIntolerance() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        config.setAddPaddingExtension(true);
        ClientHelloMessage message = new ClientHelloMessage(config);
        int newLength = 512 - 4 - getClientHelloLength(message, config);
        if (newLength > 0) {
            config.setDefaultPaddingExtensionBytes(new byte[newLength]);
        } else {
            // TODO this is currently not working as intended
        }
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasGreaseCipherSuiteIntolerance() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        Arrays.asList(CipherSuite.values()).stream()
                .filter(cipherSuite -> cipherSuite.isGrease())
                .forEach(
                        greaseCipher ->
                                config.getDefaultClientSupportedCipherSuites().add(greaseCipher));
        ClientHelloMessage message = new ClientHelloMessage(config);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasGreaseNamedGroupIntolerance() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        Arrays.asList(NamedGroup.values()).stream()
                .filter(group -> group.isGrease())
                .forEach(greaseGroup -> config.getDefaultClientNamedGroups().add(greaseGroup));
        ClientHelloMessage message = new ClientHelloMessage(config);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasGreaseSignatureAndHashAlgorithmIntolerance() {
        Config config = configSelector.getAnyWorkingBaseConfig();
        Arrays.asList(SignatureAndHashAlgorithm.values()).stream()
                .filter(algorithm -> algorithm.isGrease())
                .forEach(
                        greaseAlgorithm ->
                                config.getDefaultClientSupportedSignatureAndHashAlgorithms()
                                        .add(greaseAlgorithm));
        ClientHelloMessage message = new ClientHelloMessage(config);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.HAS_EXTENSION_INTOLERANCE, extensionIntolerance);
        put(TlsAnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE, cipherSuiteIntolerance);
        put(
                TlsAnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE,
                cipherSuiteLengthIntolerance512);
        put(TlsAnalyzedProperty.HAS_COMPRESSION_INTOLERANCE, compressionIntolerance);
        put(TlsAnalyzedProperty.HAS_VERSION_INTOLERANCE, versionIntolerance);
        put(TlsAnalyzedProperty.HAS_ALPN_INTOLERANCE, alpnIntolerance);
        put(TlsAnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE, clientHelloLengthIntolerance);
        put(
                TlsAnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE,
                emptyLastExtensionIntolerance);
        put(
                TlsAnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG,
                onlySecondCipherSuiteByteEvaluated);
        put(TlsAnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE, namedGroupIntolerant);
        put(
                TlsAnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE,
                namedSignatureAndHashAlgorithmIntolerance);
        put(TlsAnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES, ignoresCipherSuiteOffering);
        put(TlsAnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES, reflectsCipherSuiteOffering);
        put(TlsAnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS, ignoresOfferedNamedGroups);
        put(
                TlsAnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS,
                ignoresOfferedSignatureAndHashAlgorithms);
        put(TlsAnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE, maxLengthClientHelloIntolerant);
        put(TlsAnalyzedProperty.HAS_GREASE_NAMED_GROUP_INTOLERANCE, greaseNamedGroupIntolerance);
        put(TlsAnalyzedProperty.HAS_GREASE_CIPHER_SUITE_INTOLERANCE, greaseCipherSuiteIntolerance);
        put(
                TlsAnalyzedProperty.HAS_GREASE_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE,
                greaseSignatureAndHashAlgorithmIntolerance);
    }
}
