/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.http.HttpRequestMessage;
import de.rub.nds.tlsattacker.core.http.HttpResponseMessage;
import de.rub.nds.tlsattacker.core.http.header.GenericHttpHeader;
import de.rub.nds.tlsattacker.core.http.header.HostHeader;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeFalseRequirement;
import de.rub.nds.tlsscanner.core.vector.response.EqualityError;
import de.rub.nds.tlsscanner.core.vector.response.FingerprintChecker;
import de.rub.nds.tlsscanner.core.vector.response.ResponseExtractor;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.serverscanner.constants.CheckPatternType;
import de.rub.nds.tlsscanner.serverscanner.probe.mac.ByteCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.serverscanner.probe.mac.StateIndexPair;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.WorkingConfigRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class MacProbe extends TlsServerProbe {

    private List<CipherSuite> suiteList;

    private ResponseFingerprint correctFingerprint;

    private CheckPattern appPattern;
    private CheckPattern finishedPattern;
    private CheckPattern verifyPattern;

    public MacProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.MAC, configSelector);
        register(
                TlsAnalyzedProperty.MAC_CHECK_PATTERN_APP_DATA,
                TlsAnalyzedProperty.MAC_CHECK_PATTERN_FIN,
                TlsAnalyzedProperty.VERIFY_CHECK_PATTERN);
    }

    @Override
    protected void executeTest() {
        correctFingerprint = getCorrectAppDataFingerprint();
        if (correctFingerprint != null) {
            LOGGER.debug("Correct fingerprint: " + correctFingerprint.toString());
            if (receivedAppdata(correctFingerprint)) {
                appPattern = getCheckPattern(Check.APPDATA);
            } else {
                appPattern = null;
            }
            finishedPattern = getCheckPattern(Check.FINISHED);
            verifyPattern = getCheckPattern(Check.VERIFY_DATA);
        }
    }

    private boolean receivedAppdata(ResponseFingerprint fingerprint) {
        for (ProtocolMessage message : fingerprint.getMessageList()) {
            if (message instanceof ProtocolMessage
                    && message.getProtocolMessageType() == ProtocolMessageType.APPLICATION_DATA) {
                return true;
            }
        }
        return false;
    }

    private ResponseFingerprint getCorrectAppDataFingerprint() {
        Config config = configSelector.getBaseConfig();
        if (suiteList != null) {
            config.setDefaultClientSupportedCipherSuites(suiteList.get(0));
        }
        config.setWorkflowExecutorShouldClose(false);
        configSelector.repairConfig(config);
        config.setDefaultLayerConfiguration(StackConfiguration.HTTPS);
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        HttpRequestMessage httpsRequestMessage = new HttpRequestMessage();

        httpsRequestMessage.getHeader().add(new HostHeader());
        httpsRequestMessage.getHeader().add(new GenericHttpHeader("Connection", "keep-alive"));
        httpsRequestMessage
                .getHeader()
                .add(
                        new GenericHttpHeader(
                                "Accept",
                                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"));
        httpsRequestMessage
                .getHeader()
                .add(
                        new GenericHttpHeader(
                                "Accept-Encoding",
                                "compress, deflate, exi, gzip, br, bzip2, lzma, xz"));
        httpsRequestMessage
                .getHeader()
                .add(
                        new GenericHttpHeader(
                                "Accept-Language", "de-DE,de;q=0.8,en-US;q=0.6,en;q=0.4"));
        httpsRequestMessage
                .getHeader()
                .add(new GenericHttpHeader("Upgrade-Insecure-Requests", "1"));
        httpsRequestMessage
                .getHeader()
                .add(
                        new GenericHttpHeader(
                                "User-Agent",
                                "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3449.0 Safari/537.36"));

        trace.addTlsAction(new SendAction(httpsRequestMessage));
        trace.addTlsAction(new ReceiveAction(new HttpResponseMessage()));

        State state = new State(config, trace);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            ResponseFingerprint fingerprint = ResponseExtractor.getFingerprint(state);
            try {
                TlsContext tlsContext = state.getTlsContext();
                if (tlsContext.getTransportHandler() != null) {
                    tlsContext.getTransportHandler().closeConnection();
                }
            } catch (IOException ex) {
                LOGGER.warn("Could not close TransportHandler correctly", ex);
            }
            return fingerprint;
        } else {
            LOGGER.warn("Could not extract getCorrectAppDataFingerprint()");
            return null;
        }
    }

    private WorkflowTrace getAppDataTrace(Config config, int xorPosition) {
        config.setDefaultLayerConfiguration(StackConfiguration.HTTPS);
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        HttpRequestMessage httpsRequestMessage = new HttpRequestMessage();

        httpsRequestMessage.getHeader().add(new HostHeader());
        httpsRequestMessage.getHeader().add(new GenericHttpHeader("Connection", "keep-alive"));
        httpsRequestMessage
                .getHeader()
                .add(
                        new GenericHttpHeader(
                                "Accept",
                                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"));
        httpsRequestMessage
                .getHeader()
                .add(
                        new GenericHttpHeader(
                                "Accept-Encoding",
                                "compress, deflate, exi, gzip, br, bzip2, lzma, xz"));
        httpsRequestMessage
                .getHeader()
                .add(
                        new GenericHttpHeader(
                                "Accept-Language", "de-DE,de;q=0.8,en-US;q=0.6,en;q=0.4"));
        httpsRequestMessage
                .getHeader()
                .add(new GenericHttpHeader("Upgrade-Insecure-Requests", "1"));
        httpsRequestMessage
                .getHeader()
                .add(
                        new GenericHttpHeader(
                                "User-Agent",
                                "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3449.0 Safari/537.36"));

        trace.addTlsAction(new SendAction(httpsRequestMessage));
        trace.addTlsAction(new ReceiveAction(new HttpResponseMessage()));
        SendAction lastSendingAction = (SendAction) trace.getLastSendingAction();
        Record r = new Record();
        r.prepareComputations();
        ModifiableByteArray modMac = new ModifiableByteArray();
        r.getComputations().setMac(modMac);

        VariableModification<byte[]> xor =
                ByteArrayModificationFactory.xor(new byte[] {1}, xorPosition);
        modMac.setModification(xor);
        lastSendingAction.setConfiguredRecords(List.of(r));
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }

    private WorkflowTrace getVerifyDataTrace(Config config, int xorPosition) {
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        FinishedMessage lastSendMessage =
                (FinishedMessage)
                        WorkflowTraceResultUtil.getLastSentMessage(
                                trace, HandshakeMessageType.FINISHED);
        lastSendMessage.setVerifyData(Modifiable.xor(new byte[] {01}, xorPosition));
        return trace;
    }

    private WorkflowTrace getFinishedTrace(Config config, int xorPosition) {
        VariableModification<byte[]> xor =
                ByteArrayModificationFactory.xor(new byte[] {1}, xorPosition);
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(config)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
        SendAction lastSendingAction = (SendAction) trace.getLastSendingAction();
        Record r = new Record();
        r.prepareComputations();
        ModifiableByteArray modMac = new ModifiableByteArray();
        r.getComputations().setMac(modMac);
        modMac.setModification(xor);
        lastSendingAction.setConfiguredRecords(List.of(new Record(), new Record(), r));
        return trace;
    }

    private CheckPattern getCheckPattern(Check check) {
        // We do not check all cipher suite select one and test that one
        ByteCheckStatus[] macByteCheckMap;
        if (check == Check.VERIFY_DATA) {
            macByteCheckMap = getVerifyDataByteCheckMap();
        } else {
            macByteCheckMap = getMacByteCheckMap(check);
        }
        boolean allTrue = true;
        boolean allFalse = true;
        boolean checkedWithFinished = false;
        for (int i = 0; i < macByteCheckMap.length; i++) {
            if (macByteCheckMap[i] == ByteCheckStatus.NOT_CHECKED) {
                allTrue = false;
            }
            if (macByteCheckMap[i] == ByteCheckStatus.CHECKED) {
                allFalse = false;
            }
            if (macByteCheckMap[i] == ByteCheckStatus.CHECKED_WITH_FIN) {
                checkedWithFinished = true;
            }
        }
        CheckPatternType type;
        if (allFalse) {
            type = CheckPatternType.NONE;
        } else if (allTrue) {
            type = CheckPatternType.CORRECT;
        } else {
            type = CheckPatternType.PARTIAL;
        }
        return new CheckPattern(type, checkedWithFinished, macByteCheckMap);
    }

    private enum Check {
        FINISHED,
        APPDATA,
        VERIFY_DATA
    }

    private ByteCheckStatus[] getVerifyDataByteCheckMap() {
        CipherSuite suite = suiteList.get(0);
        ByteCheckStatus[] byteCheckArray = new ByteCheckStatus[12];
        List<State> stateList = new LinkedList<>();
        Config config = configSelector.getBaseConfig();
        config.setDefaultClientSupportedCipherSuites(suite);
        configSelector.repairConfig(config);
        config.setWorkflowExecutorShouldClose(false);
        List<StateIndexPair> stateIndexList = new LinkedList<>();
        for (int i = 0; i < 12; i++) {
            WorkflowTrace trace;
            trace = getVerifyDataTrace(config, i);
            State state = new State(config, trace);
            stateList.add(state);
            stateIndexList.add(new StateIndexPair(i, state));
        }
        executeState(stateList);
        for (StateIndexPair stateIndexPair : stateIndexList) {
            WorkflowTrace trace = stateIndexPair.getState().getWorkflowTrace();
            if (trace.executedAsPlanned()) {
                if (receivedOnlyFinAndCcs(trace)) {
                    byteCheckArray[stateIndexPair.getIndex()] = ByteCheckStatus.NOT_CHECKED;
                } else if (receivedFinAndCcs(trace)) {
                    byteCheckArray[stateIndexPair.getIndex()] = ByteCheckStatus.CHECKED_WITH_FIN;
                } else {
                    byteCheckArray[stateIndexPair.getIndex()] = ByteCheckStatus.CHECKED;
                }
                try {
                    TlsContext tlsContext = stateIndexPair.getState().getTlsContext();
                    if (tlsContext.getTransportHandler() != null) {
                        tlsContext.getTransportHandler().closeConnection();
                    }
                } catch (IOException ex) {
                    LOGGER.warn("Could not close TransportHandler", ex);
                }
            } else {
                byteCheckArray[stateIndexPair.getIndex()] = ByteCheckStatus.ERROR_DURING_TEST;
            }
        }
        return byteCheckArray;
    }

    private ByteCheckStatus[] getMacByteCheckMap(Check check) {
        CipherSuite suite = suiteList.get(0);
        // TODO: Protocol version not from report
        int macSize =
                AlgorithmResolver.getMacAlgorithm(ProtocolVersion.TLS12, suite)
                        .getMacLength(); // TODO
        ByteCheckStatus[] byteCheckArray = new ByteCheckStatus[macSize];
        List<State> stateList = new LinkedList<>();
        Config config = configSelector.getBaseConfig();
        config.setDefaultClientSupportedCipherSuites(suite);
        config.setDefaultSelectedCipherSuite(suite);
        config.setWorkflowExecutorShouldClose(false);
        configSelector.repairConfig(config);
        List<StateIndexPair> stateIndexList = new LinkedList<>();
        for (int i = 0; i < macSize; i++) {
            WorkflowTrace trace;
            if (check == Check.APPDATA) {
                trace = getAppDataTrace(config, i);
            } else {
                trace = getFinishedTrace(config, i);
            }
            State state = new State(config, trace);
            stateList.add(state);
            stateIndexList.add(new StateIndexPair(i, state));
        }
        executeState(stateList);
        for (StateIndexPair stateIndexPair : stateIndexList) {
            WorkflowTrace trace = stateIndexPair.getState().getWorkflowTrace();
            if (trace.executedAsPlanned()) {
                if (check == Check.APPDATA) {
                    ResponseFingerprint fingerprint =
                            ResponseExtractor.getFingerprint(stateIndexPair.getState());
                    EqualityError equalityError =
                            FingerprintChecker.checkEquality(fingerprint, correctFingerprint);
                    LOGGER.debug("Fingerprint: " + fingerprint.toString());
                    if (equalityError != EqualityError.NONE) {
                        byteCheckArray[stateIndexPair.getIndex()] = ByteCheckStatus.CHECKED;
                    } else {
                        byteCheckArray[stateIndexPair.getIndex()] = ByteCheckStatus.NOT_CHECKED;
                    }
                } else {
                    if (receivedOnlyFinAndCcs(trace)) {
                        byteCheckArray[stateIndexPair.getIndex()] = ByteCheckStatus.NOT_CHECKED;
                    } else if (receivedFinAndCcs(trace)) {
                        byteCheckArray[stateIndexPair.getIndex()] =
                                ByteCheckStatus.CHECKED_WITH_FIN;
                    } else {
                        byteCheckArray[stateIndexPair.getIndex()] = ByteCheckStatus.CHECKED;
                    }
                }
            } else {
                byteCheckArray[stateIndexPair.getIndex()] = ByteCheckStatus.ERROR_DURING_TEST;
            }
            try {
                TlsContext tlsContext = stateIndexPair.getState().getTlsContext();
                if (tlsContext.getTransportHandler() != null) {
                    tlsContext.getTransportHandler().closeConnection();
                }
            } catch (IOException ex) {
                LOGGER.warn("Could not close TransportHandler", ex);
            }
        }
        return byteCheckArray;
    }

    public boolean receivedOnlyFinAndCcs(WorkflowTrace trace) {
        return trace.getLastReceivingAction().getReceivedMessages().size() == 2
                && receivedFinAndCcs(trace);
    }

    public boolean receivedFinAndCcs(WorkflowTrace trace) {
        return WorkflowTraceResultUtil.didReceiveMessage(trace, HandshakeMessageType.FINISHED)
                && WorkflowTraceResultUtil.didReceiveMessage(
                        trace, ProtocolMessageType.CHANGE_CIPHER_SPEC);
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeFalseRequirement<ServerReport>(ProtocolType.DTLS)
                .and(new ProbeRequirement<>(TlsProbeType.CIPHER_SUITE))
                .and(
                        new PropertyTrueRequirement<>(
                                TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS,
                                TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS))
                .and(new WorkingConfigRequirement(configSelector));
    }

    @Override
    public void adjustConfig(ServerReport report) {
        List<CipherSuite> allSuiteList = new LinkedList<>();

        Set<CipherSuite> ciphersuitesResult = report.getSupportedCipherSuites();
        if (ciphersuitesResult != null) {
            allSuiteList.addAll(ciphersuitesResult);
            suiteList = new LinkedList<>();
            for (CipherSuite suite : allSuiteList) {
                if (suite.isUsingMac()) {
                    suiteList.add(suite);
                }
            }
        } else {
            allSuiteList = CipherSuite.getImplemented();
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.MAC_CHECK_PATTERN_APP_DATA, appPattern);
        put(TlsAnalyzedProperty.MAC_CHECK_PATTERN_FIN, finishedPattern);
        put(TlsAnalyzedProperty.VERIFY_CHECK_PATTERN, verifyPattern);
    }
}
