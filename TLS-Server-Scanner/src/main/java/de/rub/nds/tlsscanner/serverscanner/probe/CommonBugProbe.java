/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
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

/**
 *
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
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

    public CommonBugProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.COMMON_BUGS, config);
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

    private Config getWorkingConfig() {
        Config config = ConfigSelector.getNiceConfig(scannerConfig);
        config.setStopActionsAfterIOException(true);
        return config;
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

    private TestResult hasExtensionIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());

            ClientHelloMessage message = new ClientHelloMessage(config);
            UnknownExtensionMessage extension = new UnknownExtensionMessage();
            extension.setTypeConfig(new byte[] { (byte) 3F, (byte) 3F });
            extension.setDataConfig(new byte[] { 00, 11, 22, 33 });
            message.getExtensions().add(extension);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) ? TestResult.FALSE
                : TestResult.TRUE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasExtensionIntolerance():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasBigClientHelloIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            config.setAddPaddingExtension(true);
            config.setDefaultPaddingExtensionBytes(new byte[14000]);
            ClientHelloMessage message = new ClientHelloMessage(config);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) ? TestResult.FALSE
                : TestResult.TRUE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasBigClientHelloIntolerance():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasIgnoresSigHashAlgoOfferingBug() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            config.setAddSignatureAndHashAlgorithmsExtension(false);
            List<CipherSuite> suiteList = new LinkedList<>();
            for (CipherSuite suite : CipherSuite.getImplemented()) {
                if (suite.isEphemeral()) {
                    suiteList.add(suite);
                }
            }
            config.setDefaultClientSupportedCipherSuites(suiteList);
            config.setAddECPointFormatExtension(true);
            config.setAddEllipticCurveExtension(true);
            ClientHelloMessage message = new ClientHelloMessage(config);
            SignatureAndHashAlgorithmsExtensionMessage extension = new SignatureAndHashAlgorithmsExtensionMessage();
            extension.setSignatureAndHashAlgorithms(Modifiable.explicit(new byte[] { (byte) 0xED, (byte) 0xED }));
            message.addExtension(extension);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) ? TestResult.TRUE
                : TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasIgnoresSigHashAlgoOfferingBug():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasIgnoresNamedGroupsOfferingBug() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            config.setAddSignatureAndHashAlgorithmsExtension(true);
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
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace)) {
                LOGGER.debug("Received a SH for invalid NamedGroup, server selected: "
                    + state.getTlsContext().getSelectedGroup().name());
                return TestResult.TRUE;
            }
            return TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasIgnoresNamedGroupsOfferingBug():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private void adjustCipherSuiteSelectionBugs() {
        try {

            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            message.setCipherSuites(Modifiable.explicit(new byte[] { (byte) 0xEE, (byte) 0xCC }));
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            boolean receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
            ServerHelloMessage serverHelloMessage = (ServerHelloMessage) WorkflowTraceUtil
                .getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, trace);
            if (receivedShd) {
                if (Arrays.equals(serverHelloMessage.getSelectedCipherSuite().getValue(),
                    new byte[] { (byte) 0xEE, (byte) 0xCC })) {
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
        } catch (Exception e) {
            LOGGER.error("Could not scan for adjustCipherSuiteSelectionBugs():" + getProbeName(), e);
            reflectsCipherSuiteOffering = TestResult.ERROR_DURING_TEST;
            ignoresCipherSuiteOffering = TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasSignatureAndHashAlgorithmIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            config.setAddSignatureAndHashAlgorithmsExtension(false);
            List<CipherSuite> suiteList = new LinkedList<>();
            for (CipherSuite suite : CipherSuite.getImplemented()) {
                if (suite.isEphemeral()) {
                    suiteList.add(suite);
                }
            }
            config.setDefaultClientSupportedCipherSuites(suiteList);
            config.setAddECPointFormatExtension(true);
            config.setAddEllipticCurveExtension(true);
            ClientHelloMessage message = new ClientHelloMessage(config);
            SignatureAndHashAlgorithmsExtensionMessage extension = new SignatureAndHashAlgorithmsExtensionMessage();
            extension.setSignatureAndHashAlgorithms(Modifiable.insert(new byte[] { (byte) 0xED, (byte) 0xED }, 0));
            message.addExtension(extension);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) ? TestResult.FALSE
                : TestResult.TRUE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasSignatureAndHashAlgorithmIntolerance():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasNamedGroupIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            config.setAddSignatureAndHashAlgorithmsExtension(true);
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
            message.addExtension(extension);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            boolean receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
            if (receivedShd) {
                trace.reset();
                extension.setSupportedGroups(Modifiable.insert(new byte[] { (byte) 0xED, (byte) 0xED }, 0));
                state = new State(config, trace);
                executeState(state);
                receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
                return !receivedShd == true ? TestResult.TRUE : TestResult.FALSE;
            } else {
                return TestResult.FALSE;
            }
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasNamedGroupIntolerance():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasOnlySecondCipherSuiteByteEvaluatedBug() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
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
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            boolean receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
            return receivedShd ? TestResult.TRUE : TestResult.FALSE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasOnlySecondCipherSuiteByteEvaluatedBug():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasEmptyLastExtensionIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            ExtendedMasterSecretExtensionMessage extension = new ExtendedMasterSecretExtensionMessage();
            message.getExtensions().add(extension);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) ? TestResult.FALSE
                : TestResult.TRUE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasEmptyLastExtensionIntolerance():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasVersionIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            message.setProtocolVersion(Modifiable.explicit(new byte[] { 0x03, 0x05 }));
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) ? TestResult.FALSE
                : TestResult.TRUE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasVersionIntolerance():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasCompressionIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            message.setCompressions(new byte[] { (byte) 0xFF, (byte) 0x00 });
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) ? TestResult.FALSE
                : TestResult.TRUE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasCompressionIntolerance():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasCipherSuiteLengthIntolerance512() {
        try {
            Config config = getWorkingConfig();
            List<CipherSuite> toTestList = new LinkedList<>();
            toTestList.addAll(Arrays.asList(CipherSuite.values()));
            toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
            toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            config.setDefaultClientSupportedCipherSuites(toTestList);
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) ? TestResult.FALSE
                : TestResult.TRUE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasCipherSuiteLengthIntolerance512():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasCipherSuiteIntolerance() {
        try {
            Config config = getWorkingConfig();
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            message.setCipherSuites(Modifiable.insert(new byte[] { (byte) 0xCF, (byte) 0xAA }, 1));
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) ? TestResult.FALSE
                : TestResult.TRUE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasCipherSuiteIntolerance():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasAlpnIntolerance() {
        try {
            Config config = getWorkingConfig();
            config.setAddAlpnExtension(true);
            List<String> alpnProtocols = new LinkedList<>();
            for (AlpnProtocol protocol : AlpnProtocol.values()) {
                alpnProtocols.add(protocol.getConstant());
            }
            alpnProtocols.add("This is not an ALPN Protocol");
            config.setDefaultProposedAlpnProtocols(alpnProtocols);
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) ? TestResult.FALSE
                : TestResult.TRUE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasAlpnIntolerance():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasClientHelloLengthIntolerance() {
        try {
            Config config = ConfigSelector.getNiceConfig(scannerConfig);

            config.setAddAlpnExtension(true);
            config.setAddPaddingExtension(true);

            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);

            int newLength = 512 - 4 - getClientHelloLength(message, config);
            if (newLength > 0) {
                config.setDefaultPaddingExtensionBytes(new byte[newLength]);
            } else {
                // TODO this is currently not working as intended
            }
            message = new ClientHelloMessage(config);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) ? TestResult.FALSE
                : TestResult.TRUE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasClientHelloLengthIntolerance():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult hasGreaseCipherSuiteIntolerance() {
        Config config = getWorkingConfig();
        Arrays.asList(CipherSuite.values()).stream().filter(cipherSuite -> cipherSuite.isGrease())
            .forEach(greaseCipher -> config.getDefaultClientSupportedCipherSuites().add(greaseCipher));
        return hasGreaseIntolerance(config);
    }

    private TestResult hasGreaseNamedGroupIntolerance() {
        Config config = getWorkingConfig();
        Arrays.asList(NamedGroup.values()).stream().filter(group -> group.isGrease())
            .forEach(greaseGroup -> config.getDefaultClientNamedGroups().add(greaseGroup));
        return hasGreaseIntolerance(config);
    }

    private TestResult hasGreaseSignatureAndHashAlgorithmIntolerance() {
        Config config = getWorkingConfig();
        Arrays.asList(SignatureAndHashAlgorithm.values()).stream().filter(algorithm -> algorithm.isGrease()).forEach(
            greaseAlgorithm -> config.getDefaultClientSupportedSignatureAndHashAlgorithms().add(greaseAlgorithm));
        return hasGreaseIntolerance(config);
    }

    private TestResult hasGreaseIntolerance(Config config) {
        try {
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            WorkflowTrace trace = factory.createTlsEntryWorkflowTrace(config.getDefaultClientConnection());
            ClientHelloMessage message = new ClientHelloMessage(config);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
            State state = new State(config, trace);
            executeState(state);
            return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace) ? TestResult.FALSE
                : TestResult.TRUE;
        } catch (Exception e) {
            LOGGER.error("Could not scan for hasGreaseIntolerance():" + getProbeName(), e);
            return TestResult.ERROR_DURING_TEST;
        }
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
