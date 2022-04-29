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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlpnProtocol;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
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
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.CommonBugProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class CommonBugProbe extends TlsProbe {

    // does it handle unknown extensions correctly?
    private TestResult extensionIntolerance;
    // does it handle unknown cipher suites correctly?
    private TestResult cipherSuiteIntolerance;
    // does it handle long cipher suite length values correctly?
    private TestResult cipherSuiteLengthIntolerance512;
    // does it handle unknown compression algorithms correctly?
    private TestResult compressionIntolerance;
    // does it handle unknown versions correctly?
    private TestResult versionIntolerance;
    // does it handle unknown alpn strings correctly?
    private TestResult alpnIntolerance;
    // 256 - 511 <-- ch should be bigger than this?
    private TestResult clientHelloLengthIntolerance;
    // does it break on empty last extension?
    private TestResult emptyLastExtensionIntolerance;
    // is only the second byte of the cipher suite evaluated?
    private TestResult onlySecondCipherSuiteByteEvaluated;
    // does it handle unknown groups correctly?
    private TestResult namedGroupIntolerant;
    // does it handle signature and hash algorithms correctly?
    private TestResult namedSignatureAndHashAlgorithmIntolerance;
    // does it ignore the offered cipher suites?
    private TestResult ignoresCipherSuiteOffering;
    // does it reflect the offered cipher suites?
    private TestResult reflectsCipherSuiteOffering;
    // does it ignore the offered named groups?
    private TestResult ignoresOfferedNamedGroups;
    // does it ignore the sig hash algorithms?
    private TestResult ignoresOfferedSignatureAndHashAlgorithms;
    // server does not like really big client hello messages
    private TestResult maxLengthClientHelloIntolerant;
    // does it accept grease values in the supported groups extension?
    private TestResult greaseNamedGroupIntolerance;
    // does it accept grease values in the cipher suites list?
    private TestResult greaseCipherSuiteIntolerance;
    // does it accept grease values in the signature and hash algorithms extension?
    private TestResult greaseSignatureAndHashAlgorithmIntolerance;

    public CommonBugProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.COMMON_BUGS, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
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
        greaseSignatureAndHashAlgorithmIntolerance = hasGreaseSignatureAndHashAlgorithmIntolerance();
        return new CommonBugProbeResult(extensionIntolerance, cipherSuiteIntolerance, cipherSuiteLengthIntolerance512,
            compressionIntolerance, versionIntolerance, alpnIntolerance, clientHelloLengthIntolerance,
            emptyLastExtensionIntolerance, onlySecondCipherSuiteByteEvaluated, namedGroupIntolerant,
            namedSignatureAndHashAlgorithmIntolerance, ignoresCipherSuiteOffering, reflectsCipherSuiteOffering,
            ignoresOfferedNamedGroups, ignoresOfferedSignatureAndHashAlgorithms, maxLengthClientHelloIntolerant,
            greaseNamedGroupIntolerance, greaseCipherSuiteIntolerance, greaseSignatureAndHashAlgorithmIntolerance);

    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    private int getClientHelloLength(ClientHelloMessage message, Config config) {
        TlsContext context = new TlsContext(config);
        ClientHelloPreparator preparator = new ClientHelloPreparator(context.getChooser(), message);
        preparator.prepare();
        ClientHelloSerializer serializer =
            new ClientHelloSerializer(message, config.getDefaultHighestClientProtocolVersion());
        return serializer.serialize().length;
    }

    private WorkflowTrace getWorkflowTrace(Config config, ClientHelloMessage clientHello) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
        trace.addTlsAction(new SendAction(clientHello));
        if (config.getHighestProtocolVersion().isDTLS() && config.isDtlsCookieExchange()) {
            trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage(config)));
            trace.addTlsAction(new SendAction(clientHello));
        }
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        return trace;
    }

    private TestResult getResult(Config config, WorkflowTrace trace, boolean checkForTrue) {
        try {
            State state = new State(config, trace);
            executeState(state);
            return checkForTrue == WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace)
                ? TestResult.TRUE : TestResult.FALSE;
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not scan for " + getProbeName(), e);
            }
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasExtensionIntolerance() {
        Config config = getConfigSelector().getBaseConfig();
        ClientHelloMessage message = new ClientHelloMessage(config);
        UnknownExtensionMessage extension = new UnknownExtensionMessage();
        extension.setTypeConfig(new byte[] { (byte) 3F, (byte) 3F });
        extension.setDataConfig(new byte[] { 00, 11, 22, 33 });
        message.getExtensions().add(extension);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasBigClientHelloIntolerance() {
        Config config = getConfigSelector().getBaseConfig();
        config.setAddPaddingExtension(true);
        config.setDefaultPaddingExtensionBytes(new byte[14000]);
        ClientHelloMessage message = new ClientHelloMessage(config);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasIgnoresSigHashAlgoOfferingBug() {
        Config config = getConfigSelector().getBaseConfig();
        config.setAddSignatureAndHashAlgorithmsExtension(false);
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isEphemeral()) {
                suiteList.add(suite);
            }
        }
        config.setDefaultClientSupportedCipherSuites(suiteList);
        getConfigSelector().repairConfig(config);
        ClientHelloMessage message = new ClientHelloMessage(config);
        SignatureAndHashAlgorithmsExtensionMessage extension = new SignatureAndHashAlgorithmsExtensionMessage();
        extension.setSignatureAndHashAlgorithms(Modifiable.explicit(new byte[] { (byte) 0xED, (byte) 0xED }));
        message.addExtension(extension);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasIgnoresNamedGroupsOfferingBug() {
        Config config = getConfigSelector().getBaseConfig();
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
        extension.setSupportedGroups(Modifiable.explicit(new byte[] { (byte) 0xED, (byte) 0xED }));
        message.addExtension(extension);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private void adjustCipherSuiteSelectionBugs() {
        Config config = getConfigSelector().getBaseConfig();
        ClientHelloMessage message = new ClientHelloMessage(config);
        message.setCipherSuites(Modifiable.explicit(new byte[] { (byte) 0xEE, (byte) 0xCC }));
        WorkflowTrace trace = getWorkflowTrace(config, message);
        State state = new State(config, trace);
        executeState(state);
        TestResult receivedShd = getResult(config, trace, true);
        if (receivedShd == TestResult.TRUE) {
            ServerHelloMessage serverHelloMessage = (ServerHelloMessage) WorkflowTraceUtil
                .getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, trace);
            if (Arrays.equals(serverHelloMessage.getSelectedCipherSuite().getValue(),
                new byte[] { (byte) 0xEE, (byte) 0xCC })) {
                reflectsCipherSuiteOffering = TestResult.TRUE;
                ignoresCipherSuiteOffering = TestResult.FALSE;
            } else {
                reflectsCipherSuiteOffering = TestResult.FALSE;
                ignoresCipherSuiteOffering = TestResult.TRUE;
            }
        } else if (receivedShd == TestResult.FALSE) {
            reflectsCipherSuiteOffering = TestResult.FALSE;
            ignoresCipherSuiteOffering = TestResult.FALSE;
        } else if (receivedShd == TestResult.ERROR_DURING_TEST) {
            reflectsCipherSuiteOffering = TestResult.ERROR_DURING_TEST;
            ignoresCipherSuiteOffering = TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasSignatureAndHashAlgorithmIntolerance() {
        Config config = getConfigSelector().getBaseConfig();
        config.setAddSignatureAndHashAlgorithmsExtension(false);
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isEphemeral()) {
                suiteList.add(suite);
            }
        }
        config.setDefaultClientSupportedCipherSuites(suiteList);
        getConfigSelector().repairConfig(config);
        ClientHelloMessage message = new ClientHelloMessage(config);
        SignatureAndHashAlgorithmsExtensionMessage extension = new SignatureAndHashAlgorithmsExtensionMessage();
        extension.setSignatureAndHashAlgorithms(Modifiable.insert(new byte[] { (byte) 0xED, (byte) 0xED }, 0));
        message.addExtension(extension);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasNamedGroupIntolerance() {
        Config config = getConfigSelector().getBaseConfig();
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
        extension.setSupportedGroups(Modifiable.insert(new byte[] { (byte) 0xED, (byte) 0xED }, 0));
        message.addExtension(extension);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasOnlySecondCipherSuiteByteEvaluatedBug() {
        Config config = getConfigSelector().getBaseConfig();
        ClientHelloMessage message = new ClientHelloMessage(config);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.getByteValue()[0] == 0x00) {
                try {
                    stream.write(new byte[] { (byte) 0xDF, suite.getByteValue()[1] });
                } catch (IOException ex) {
                    LOGGER.debug(ex);
                }
            }
        }
        message.setCipherSuites(Modifiable.explicit(stream.toByteArray()));
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, true);
    }

    private TestResult hasEmptyLastExtensionIntolerance() {
        Config config = getConfigSelector().getBaseConfig();
        ClientHelloMessage message = new ClientHelloMessage(config);
        ExtendedMasterSecretExtensionMessage extension = new ExtendedMasterSecretExtensionMessage();
        message.getExtensions().add(extension);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasVersionIntolerance() {
        Config config = getConfigSelector().getBaseConfig();
        ClientHelloMessage message = new ClientHelloMessage(config);
        message.setProtocolVersion(Modifiable.explicit(new byte[] { 0x03, 0x05 }));
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasCompressionIntolerance() {
        Config config = getConfigSelector().getBaseConfig();
        ClientHelloMessage message = new ClientHelloMessage(config);
        message.setCompressions(new byte[] { (byte) 0xFF, (byte) 0x00 });
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasCipherSuiteLengthIntolerance512() {
        Config config = getConfigSelector().getBaseConfig();
        List<CipherSuite> toTestList = new LinkedList<>();
        toTestList.addAll(Arrays.asList(CipherSuite.values()));
        toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
        toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        config.setDefaultClientSupportedCipherSuites(toTestList);
        getConfigSelector().repairConfig(config);
        ClientHelloMessage message = new ClientHelloMessage(config);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasCipherSuiteIntolerance() {
        Config config = getConfigSelector().getBaseConfig();
        ClientHelloMessage message = new ClientHelloMessage(config);
        message.setCipherSuites(Modifiable.insert(new byte[] { (byte) 0xCF, (byte) 0xAA }, 1));
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasAlpnIntolerance() {
        Config config = getConfigSelector().getBaseConfig();
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
        Config config = getConfigSelector().getBaseConfig();
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
        Config config = getConfigSelector().getBaseConfig();
        Arrays.asList(CipherSuite.values()).stream().filter(cipherSuite -> cipherSuite.isGrease())
            .forEach(greaseCipher -> config.getDefaultClientSupportedCipherSuites().add(greaseCipher));
        ClientHelloMessage message = new ClientHelloMessage(config);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasGreaseNamedGroupIntolerance() {
        Config config = getConfigSelector().getBaseConfig();
        Arrays.asList(NamedGroup.values()).stream().filter(group -> group.isGrease())
            .forEach(greaseGroup -> config.getDefaultClientNamedGroups().add(greaseGroup));
        ClientHelloMessage message = new ClientHelloMessage(config);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    private TestResult hasGreaseSignatureAndHashAlgorithmIntolerance() {
        Config config = getConfigSelector().getBaseConfig();
        Arrays.asList(SignatureAndHashAlgorithm.values()).stream().filter(algorithm -> algorithm.isGrease()).forEach(
            greaseAlgorithm -> config.getDefaultClientSupportedSignatureAndHashAlgorithms().add(greaseAlgorithm));
        ClientHelloMessage message = new ClientHelloMessage(config);
        WorkflowTrace trace = getWorkflowTrace(config, message);
        return getResult(config, trace, false);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new CommonBugProbeResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
            TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
            TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
            TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
            TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }
}
