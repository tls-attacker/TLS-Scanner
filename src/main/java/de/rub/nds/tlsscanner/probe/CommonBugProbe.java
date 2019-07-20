/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
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
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.CommonBugProbeResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.selector.ConfigSelector;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CommonBugProbe extends TlsProbe {

    private TestResult extensionIntolerance; //does it handle unknown extenstions correctly?
    private TestResult cipherSuiteIntolerance; //does it handle unknown ciphersuites correctly?
    private TestResult cipherSuiteLengthIntolerance512; //does it handle long ciphersuite length values correctly?
    private TestResult compressionIntolerance; //does it handle unknown compression algorithms correctly
    private TestResult versionIntolerance; //does it handle unknown versions correctly?
    private TestResult alpnIntolerance; //does it handle unknown alpn strings correctly?
    private TestResult clientHelloLengthIntolerance; // 256 - 511 <-- ch should be bigger than this
    private TestResult emptyLastExtensionIntolerance; //does it break on empty last extension
    private TestResult onlySecondCiphersuiteByteEvaluated; //is only the second byte of the ciphersuite evaluated
    private TestResult namedGroupIntolerant; // does it handle unknown groups correctly
    private TestResult namedSignatureAndHashAlgorithmIntolerance; // does it handle signature and hash algorithms correctly
    private TestResult ignoresCipherSuiteOffering; //does it ignore the offered ciphersuites
    private TestResult reflectsCipherSuiteOffering; //does it ignore the offered ciphersuites
    private TestResult ignoresOfferedNamedGroups; //does it ignore the offered named groups
    private TestResult ignoresOfferedSignatureAndHashAlgorithms; //does it ignore the sig hash algorithms
    private TestResult maxLengthClientHelloIntolerant; // server does not like really big client hello messages

    public CommonBugProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.COMMON_BUGS, config, 1);
    }

    @Override
    public ProbeResult executeTest() {
        extensionIntolerance = hasExtensionIntolerance();
        cipherSuiteIntolerance = hasCiphersuiteIntolerance();
        cipherSuiteLengthIntolerance512 = hasCiphersuiteLengthIntolerance512();
        compressionIntolerance = hasCompressionIntolerance();
        versionIntolerance = hasVersionIntolerance();
        alpnIntolerance = hasAlpnIntolerance();
        clientHelloLengthIntolerance = hasClientHelloLengthIntolerance();
        emptyLastExtensionIntolerance = hasEmptyLastExtensionIntolerance();
        onlySecondCiphersuiteByteEvaluated = hasOnlySecondCiphersuiteByteEvaluatedBug();
        namedGroupIntolerant = hasNamedGroupIntolerance();
        namedSignatureAndHashAlgorithmIntolerance = hasSignatureAndHashAlgorithmIntolerance();
        adjustCipherSuiteSelectionBugs();
        ignoresOfferedNamedGroups = hasIgnoresNamedGroupsOfferingBug();
        ignoresOfferedSignatureAndHashAlgorithms = hasIgnoresSigHashAlgoOfferingBug();
        maxLengthClientHelloIntolerant = hasBigClientHelloIntolerance();
        return new CommonBugProbeResult(extensionIntolerance, cipherSuiteIntolerance, cipherSuiteLengthIntolerance512, compressionIntolerance, versionIntolerance, alpnIntolerance, clientHelloLengthIntolerance, emptyLastExtensionIntolerance, onlySecondCiphersuiteByteEvaluated, namedGroupIntolerant, namedSignatureAndHashAlgorithmIntolerance, ignoresCipherSuiteOffering, reflectsCipherSuiteOffering, ignoresOfferedNamedGroups, ignoresOfferedSignatureAndHashAlgorithms, maxLengthClientHelloIntolerant);

    }

    private Config getWorkingConfig() {
        Config config = ConfigSelector.getNiceConfig(scannerConfig);

        return config;
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new CommonBugProbeResult(TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED, TestResult.UNTESTED);
    }

    private int getClientHelloLength(ClientHelloMessage message, Config config) {
        TlsContext context = new TlsContext(config);
        ClientHelloPreparator preparator = new ClientHelloPreparator(context.getChooser(), message);
        preparator.prepare();
        ClientHelloSerializer serializer = new ClientHelloSerializer(message, config.getDefaultHighestClientProtocolVersion());
        return serializer.serialize().length;
    }

    private TestResult hasExtensionIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());

            ClientHelloMessage message = new ClientHelloMessage(config);
            UnknownExtensionMessage extension = new UnknownExtensionMessage();
            extension.setTypeConfig(new byte[]{(byte) 3F, (byte) 3F});
            extension.setDataConfig(new byte[]{00, 11, 22, 33});
            message.getExtensions().add(extension);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) == true ? TestResult.TRUE : TestResult.FALSE;
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasBigClientHelloIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
            config.setAddPaddingExtension(true);
            config.setPaddingLength(65535);
            ClientHelloMessage message = new ClientHelloMessage(config);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) == true ? TestResult.TRUE : TestResult.FALSE;
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasIgnoresSigHashAlgoOfferingBug() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
            config.setAddSignatureAndHashAlgorithmsExtension(false);
            List<CipherSuite> suiteList = new LinkedList<>();
            for (CipherSuite suite : CipherSuite.getImplemented()) {
                if (suite.isEphemeral()) {
                    suiteList.add(suite);
                }
            }
            config.setDefaultClientSupportedCiphersuites(suiteList);
            config.setAddECPointFormatExtension(true);
            config.setAddEllipticCurveExtension(true);
            ClientHelloMessage message = new ClientHelloMessage(config);
            SignatureAndHashAlgorithmsExtensionMessage extension = new SignatureAndHashAlgorithmsExtensionMessage();
            extension.setSignatureAndHashAlgorithms(Modifiable.explicit(new byte[]{(byte) 0xED, (byte) 0xED}));
            message.addExtension(extension);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) == true ? TestResult.TRUE : TestResult.FALSE;
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasIgnoresNamedGroupsOfferingBug() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
            config.setAddSignatureAndHashAlgorithmsExtension(true);
            List<CipherSuite> suiteList = new LinkedList<>();
            for (CipherSuite suite : CipherSuite.getImplemented()) {
                if (suite.isEphemeral() && suite.name().contains("EC")) {
                    suiteList.add(suite);
                }
            }
            config.setDefaultClientSupportedCiphersuites(suiteList);
            config.setAddECPointFormatExtension(true);
            config.setAddEllipticCurveExtension(false);
            ClientHelloMessage message = new ClientHelloMessage(config);
            EllipticCurvesExtensionMessage extension = new EllipticCurvesExtensionMessage();
            extension.setSupportedGroups(Modifiable.explicit(new byte[]{(byte) 0xED, (byte) 0xED}));
            message.addExtension(extension);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            boolean receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
            if (receivedShd) {
                LOGGER.debug("Received a SH for invalid NamedGroup, server selected: " + state.getTlsContext().getSelectedGroup().name());
            }
            return receivedShd == true ? TestResult.TRUE : TestResult.FALSE;
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private void adjustCipherSuiteSelectionBugs() {
        Config config = getWorkingConfig();
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
        ClientHelloMessage message = new ClientHelloMessage(config);
        message.setCipherSuites(Modifiable.explicit(new byte[]{(byte) 0xEE, (byte) 0xCC}));
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        executeState(state);
        boolean receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
        ServerHelloMessage serverHelloMessage = (ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, trace);
        if (receivedShd) {
            if (Arrays.equals(serverHelloMessage.getSelectedCipherSuite().getValue(), new byte[]{(byte) 0xEE, (byte) 0xCC})) {
                reflectsCipherSuiteOffering = TestResult.TRUE;
                ignoresCipherSuiteOffering = TestResult.FALSE;
            } else {
                reflectsCipherSuiteOffering = TestResult.FALSE;
                ignoresCipherSuiteOffering = TestResult.TRUE;
            }
        } else {
            reflectsCipherSuiteOffering = TestResult.FALSE;
            ignoresCipherSuiteOffering = TestResult.FALSE;
        }
    }

    private TestResult hasSignatureAndHashAlgorithmIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
            config.setAddSignatureAndHashAlgorithmsExtension(false);
            List<CipherSuite> suiteList = new LinkedList<>();
            for (CipherSuite suite : CipherSuite.getImplemented()) {
                if (suite.isEphemeral()) {
                    suiteList.add(suite);
                }
            }
            config.setDefaultClientSupportedCiphersuites(suiteList);
            config.setAddECPointFormatExtension(true);
            config.setAddEllipticCurveExtension(true);
            ClientHelloMessage message = new ClientHelloMessage(config);
            SignatureAndHashAlgorithmsExtensionMessage extension = new SignatureAndHashAlgorithmsExtensionMessage();
            extension.setSignatureAndHashAlgorithms(Modifiable.insert(new byte[]{(byte) 0xED, (byte) 0xED}, 0));
            message.addExtension(extension);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) == true ? TestResult.TRUE : TestResult.FALSE;
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasNamedGroupIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
            config.setAddSignatureAndHashAlgorithmsExtension(true);
            List<CipherSuite> suiteList = new LinkedList<>();
            for (CipherSuite suite : CipherSuite.getImplemented()) {
                if (suite.isEphemeral() && suite.name().contains("EC")) {
                    suiteList.add(suite);
                }
            }
            config.setDefaultClientSupportedCiphersuites(suiteList);
            config.setAddECPointFormatExtension(true);
            config.setAddEllipticCurveExtension(false);
            ClientHelloMessage message = new ClientHelloMessage(config);
            EllipticCurvesExtensionMessage extension = new EllipticCurvesExtensionMessage();
            message.addExtension(extension);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            boolean receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
            if (receivedShd) {
                trace.reset();
                extension.setSupportedGroups(Modifiable.insert(new byte[]{(byte) 0xED, (byte) 0xED}, 0));
                state = new State(config, trace);
                executeState(state);
                receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
                return !receivedShd == true ? TestResult.TRUE : TestResult.FALSE;
            } else {
                return TestResult.FALSE;
            }
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasOnlySecondCiphersuiteByteEvaluatedBug() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            for (CipherSuite suite : CipherSuite.values()) {
                if (suite.getByteValue()[0] == 0x00) {
                    try {
                        stream.write(new byte[]{(byte) 0xDF, suite.getByteValue()[1]});
                    } catch (IOException ex) {
                        LOGGER.debug(ex);
                    }
                }
            }
            message.setCipherSuites(Modifiable.explicit(stream.toByteArray()));
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            boolean receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
            return receivedShd  == true ? TestResult.TRUE : TestResult.FALSE;
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasEmptyLastExtensionIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            ExtendedMasterSecretExtensionMessage extension = new ExtendedMasterSecretExtensionMessage();
            message.getExtensions().add(extension);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) == true ? TestResult.TRUE : TestResult.FALSE;
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasVersionIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            message.setProtocolVersion(Modifiable.explicit(new byte[]{0x03, 0x05}));
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) == true ? TestResult.TRUE : TestResult.FALSE;
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasCompressionIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            message.setCompressions(new byte[]{(byte) 0xFF, (byte) 0x00});
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) == true ? TestResult.TRUE : TestResult.FALSE;
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasCiphersuiteLengthIntolerance512() {
        try {
            Config config = getWorkingConfig();
            List<CipherSuite> toTestList = new LinkedList<>();
            toTestList.addAll(Arrays.asList(CipherSuite.values()));
            toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
            toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            config.setDefaultClientSupportedCiphersuites(toTestList);
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) == true ? TestResult.TRUE : TestResult.FALSE;
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasCiphersuiteIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            message.setCipherSuites(Modifiable.insert(new byte[]{(byte) 0xCF, (byte) 0xAA}, 1));
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) == true ? TestResult.TRUE : TestResult.FALSE;
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasAlpnIntolerance() {
        try {
            Config config = getWorkingConfig();
            config.setAddAlpnExtension(true);
            config.setAlpnAnnouncedProtocols(new String[]{"This is not an ALPN Protocol"});
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) == true ? TestResult.TRUE : TestResult.FALSE;
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasClientHelloLengthIntolerance() {
        try {
            Config config = getWorkingConfig();
            config.setAddAlpnExtension(true);
            config.setAddPaddingExtension(true);

            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            int newLength = 384 - getClientHelloLength(message, config) - config.getPaddingLength();
            config.setPaddingLength(newLength);
            message = new ClientHelloMessage(config);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) == true ? TestResult.TRUE : TestResult.FALSE;
        } catch(Exception e) {
            return TestResult.ERROR_DURING_TEST;
        }
    }
}
