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
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.CommonBugProbeResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
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

    private Boolean extensionIntolerance; //does it handle unknown extenstions correctly?
    private Boolean cipherSuiteIntolerance; //does it handle unknown ciphersuites correctly?
    private Boolean cipherSuiteLengthIntolerance512; //does it handle long ciphersuite length values correctly?
    private Boolean compressionIntolerance; //does it handle unknown compression algorithms correctly
    private Boolean versionIntolerance; //does it handle unknown versions correctly?
    private Boolean alpnIntolerance; //does it handle unknown alpn strings correctly?
    private Boolean clientHelloLengthIntolerance; // 256 - 511 <-- ch should be bigger than this
    private Boolean emptyLastExtensionIntolerance; //does it break on empty last extension
    private Boolean onlySecondCiphersuiteByteEvaluated; //is only the second byte of the ciphersuite evaluated
    private Boolean namedGroupIntolerant; // does it handle unknown groups correctly
    private Boolean namedSignatureAndHashAlgorithmIntolerance; // does it handle signature and hash algorithms correctly
    private Boolean ignoresCipherSuiteOffering; //does it ignore the offered ciphersuites
    private Boolean reflectsCipherSuiteOffering; //does it ignore the offered ciphersuites
    private Boolean ignoresOfferedNamedGroups; //does it ignore the offered named groups
    private Boolean ignoresOfferedSignatureAndHashAlgorithms; //does it ignore the sig hash algorithms
    private Boolean maxLengthClientHelloIntolerant; // server does not like really big client hello messages

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
        Config config = scannerConfig.createConfig();

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
        return new CommonBugProbeResult(extensionIntolerance, cipherSuiteIntolerance, cipherSuiteLengthIntolerance512, compressionIntolerance, versionIntolerance, alpnIntolerance, clientHelloLengthIntolerance, emptyLastExtensionIntolerance, onlySecondCiphersuiteByteEvaluated, namedGroupIntolerant, namedSignatureAndHashAlgorithmIntolerance, ignoresCipherSuiteOffering, reflectsCipherSuiteOffering, ignoresOfferedNamedGroups, ignoresOfferedSignatureAndHashAlgorithms, maxLengthClientHelloIntolerant);
    }

    private int getClientHelloLength(ClientHelloMessage message, Config config) {
        TlsContext context = new TlsContext(config);
        ClientHelloPreparator preparator = new ClientHelloPreparator(context.getChooser(), message);
        preparator.prepare();
        ClientHelloSerializer serializer = new ClientHelloSerializer(message, config.getDefaultHighestClientProtocolVersion());
        return serializer.serialize().length;
    }

    private boolean hasExtensionIntolerance() {
        Config config = getWorkingConfig();
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage message = new ClientHelloMessage(config);
        UnknownExtensionMessage extension = new UnknownExtensionMessage();
        extension.setTypeConfig(new byte[]{(byte) 3F, (byte) 3F});
        extension.setDataConfig(new byte[]{00, 11, 22, 33});
        message.getExtensions().add(extension);
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        parallelExecutor.bulkExecute(state);
        return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
    }

    private Boolean hasBigClientHelloIntolerance() {
        Config config = getWorkingConfig();
        WorkflowTrace trace = new WorkflowTrace();
        config.setAddPaddingExtension(true);
        config.setPaddingLength(65535);
        ClientHelloMessage message = new ClientHelloMessage(config);
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        parallelExecutor.bulkExecute(state);
        return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
    }

    private Boolean hasIgnoresSigHashAlgoOfferingBug() {
        Config config = getWorkingConfig();
        WorkflowTrace trace = new WorkflowTrace();
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
        parallelExecutor.bulkExecute(state);
        return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
    }

    private Boolean hasIgnoresNamedGroupsOfferingBug() {
        Config config = getWorkingConfig();
        WorkflowTrace trace = new WorkflowTrace();
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
        parallelExecutor.bulkExecute(state);
        boolean receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
        if (receivedShd) {
            LOGGER.debug("Received a SH for invalid NamedGroup, server selected: " + state.getTlsContext().getSelectedGroup().name());
        }
        return receivedShd;
    }

    private void adjustCipherSuiteSelectionBugs() {
        Config config = getWorkingConfig();
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage message = new ClientHelloMessage(config);
        message.setCipherSuites(Modifiable.explicit(new byte[]{(byte) 0xEE, (byte) 0xCC}));
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        parallelExecutor.bulkExecute(state);
        boolean receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
        ServerHelloMessage serverHelloMessage = (ServerHelloMessage) WorkflowTraceUtil.getFirstReceivedMessage(HandshakeMessageType.SERVER_HELLO, trace);
        if (receivedShd) {
            if (Arrays.equals(serverHelloMessage.getSelectedCipherSuite().getValue(), new byte[]{(byte) 0xEE, (byte) 0xCC})) {
                reflectsCipherSuiteOffering = true;
                ignoresCipherSuiteOffering = false;
            } else {
                reflectsCipherSuiteOffering = false;
                ignoresCipherSuiteOffering = true;
            }
        } else {
            reflectsCipherSuiteOffering = false;
            ignoresCipherSuiteOffering = false;
        }
    }

    private Boolean hasSignatureAndHashAlgorithmIntolerance() {
        Config config = getWorkingConfig();
        WorkflowTrace trace = new WorkflowTrace();
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
        parallelExecutor.bulkExecute(state);
        return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
    }

    private Boolean hasNamedGroupIntolerance() {
        Config config = getWorkingConfig();
        WorkflowTrace trace = new WorkflowTrace();
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
        parallelExecutor.bulkExecute(state);
        boolean receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
        if (receivedShd) {
            trace.reset();
            extension.setSupportedGroups(Modifiable.insert(new byte[]{(byte) 0xED, (byte) 0xED}, 0));
            state = new State(config, trace);
            parallelExecutor.bulkExecute(state);
            receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
            return !receivedShd;
        } else {
            return false;
        }
    }

    private Boolean hasOnlySecondCiphersuiteByteEvaluatedBug() {
        Config config = getWorkingConfig();
        WorkflowTrace trace = new WorkflowTrace();
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
        parallelExecutor.bulkExecute(state);
        boolean receivedShd = WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
        return receivedShd;
    }

    private Boolean hasEmptyLastExtensionIntolerance() {
        Config config = getWorkingConfig();
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage message = new ClientHelloMessage(config);
        ExtendedMasterSecretExtensionMessage extension = new ExtendedMasterSecretExtensionMessage();
        message.getExtensions().add(extension);
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        parallelExecutor.bulkExecute(state);
        return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
    }

    private Boolean hasVersionIntolerance() {
        Config config = getWorkingConfig();
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage message = new ClientHelloMessage(config);
        message.setProtocolVersion(Modifiable.explicit(new byte[]{0x03, 0x05}));
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        parallelExecutor.bulkExecute(state);
        return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
    }

    private Boolean hasCompressionIntolerance() {
        Config config = getWorkingConfig();
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage message = new ClientHelloMessage(config);
        message.setCompressions(new byte[]{(byte) 0xFF, (byte) 0x00});
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        parallelExecutor.bulkExecute(state);
        return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
    }

    private Boolean hasCiphersuiteLengthIntolerance512() {
        Config config = getWorkingConfig();
        List<CipherSuite> toTestList = new LinkedList<>();
        toTestList.addAll(Arrays.asList(CipherSuite.values()));
        toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
        toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        config.setDefaultClientSupportedCiphersuites(toTestList);
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage message = new ClientHelloMessage(config);
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        parallelExecutor.bulkExecute(state);
        return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
    }

    private Boolean hasCiphersuiteIntolerance() {
        Config config = getWorkingConfig();
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage message = new ClientHelloMessage(config);
        message.setCipherSuites(Modifiable.insert(new byte[]{(byte) 0xCF, (byte) 0xAA}, 1));
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        parallelExecutor.bulkExecute(state);
        return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
    }

    private Boolean hasAlpnIntolerance() {
        Config config = getWorkingConfig();
        config.setAddAlpnExtension(true);
        config.setAlpnAnnouncedProtocols(new String[]{"This is not an ALPN Protocol"});
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage message = new ClientHelloMessage(config);
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        parallelExecutor.bulkExecute(state);
        return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
    }

    private Boolean hasClientHelloLengthIntolerance() {
        Config config = getWorkingConfig();
        config.setAddAlpnExtension(true);
        config.setAddPaddingExtension(true);
        
        WorkflowTrace trace = new WorkflowTrace();
        ClientHelloMessage message = new ClientHelloMessage(config);
        int newLength = 384 - getClientHelloLength(message, config) - config.getPaddingLength();
        config.setPaddingLength(newLength);
        message = new ClientHelloMessage(config);
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage(config)));
        State state = new State(config, trace);
        parallelExecutor.bulkExecute(state);
        return !WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, trace);
    }
}
