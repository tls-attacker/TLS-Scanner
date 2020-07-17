/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.modifiablevariable.string.StringModificationFactory;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.exceptions.TransportHandlerConnectException;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.header.HostHeader;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.TlsRngResult;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import org.apache.commons.lang3.ArrayUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 *
 * @author Dennis Ziebart - dziebart@mail.uni-paderborn.de
 */
public class TlsRngProbe extends TlsProbe {

    private ProtocolVersion highestVersion;
    private SiteReport latestReport;
    private LinkedList<ComparableByteArray> extractedIVList;
    private LinkedList<ComparableByteArray> extractedRandomList;
    private LinkedList<ComparableByteArray> extractedSessionIDList;
    private final int SERVER_RANDOM_SIZE = 32;
    private final int IV_SIZE = 16;
    private final int NUMBER_OF_HANDSHAKES = 600;
    private final int CLIENT_RANDOM_START = 1;
    private final int IV_BLOCKS = 4000;
    private final int UNIX_TIME_ALLOWED_DEVIATION = 30;

    public TlsRngProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RNG, config);
    }

    @Override
    public ProbeResult executeTest() {
        extractedIVList = new LinkedList<>();
        extractedRandomList = new LinkedList<>();
        extractedSessionIDList = new LinkedList<>();

        // Ensure we use the highest Protocol version possible to prevent the
        // downgrade-attack mitigation to
        // activate
        if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.TRUE) {
            LOGGER.warn("SETTING HIGHEST VERSION TO TLS13");
            highestVersion = ProtocolVersion.TLS13;
            checkForUnixTime();
            collectServerRandomTls13(NUMBER_OF_HANDSHAKES, CLIENT_RANDOM_START);
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.TRUE) {
            LOGGER.warn("SETTING HIGHEST VERSION TO TLS12");
            highestVersion = ProtocolVersion.TLS12;
            checkForUnixTime();
            collectServerRandom(NUMBER_OF_HANDSHAKES, CLIENT_RANDOM_START);
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.TRUE) {
            LOGGER.warn("SETTING HIGHEST VERSION TO TLS11");
            highestVersion = ProtocolVersion.TLS11;
            checkForUnixTime();
            collectServerRandom(NUMBER_OF_HANDSHAKES, CLIENT_RANDOM_START);
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.TRUE) {
            LOGGER.warn("SETTING HIGHEST VERSION TO TLS10");
            highestVersion = ProtocolVersion.TLS10;
            checkForUnixTime();
            collectServerRandom(NUMBER_OF_HANDSHAKES, CLIENT_RANDOM_START);
        }

        // ////////////////////////////////////////////////////////////////////////////////////////////////////
        collectIV(IV_BLOCKS, CLIENT_RANDOM_START + NUMBER_OF_HANDSHAKES + 50);
        // /////////////////////////////////////////////////////////////////////////////////////////////////////

        // TODO: Implement this right.
        boolean successfulHandshake = true;

        TlsRngResult rng_extract = new TlsRngResult(successfulHandshake, extractedIVList, extractedRandomList,
                extractedSessionIDList);

        return rng_extract;
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_RSA) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_SESSION_IDS) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.HAS_EXTENSION_INTOLERANCE) == TestResult.NOT_TESTED_YET) {
            return false;
        } else {
            // We will conduct the rng extraction based on the test-results, so
            // we need those properties to be tested
            // before we conduct the RNG-Probe latestReport = report;
            this.latestReport = report;
            return true;
        }
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new TlsRngResult(false, null, null, null);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    private Config generateTestConfig(byte[] clientRandom) {
        Config testConf = getScannerConfig().createConfig();

        testConf.setEnforceSettings(false);
        testConf.setAddServerNameIndicationExtension(false);
        testConf.setAddEllipticCurveExtension(true);
        testConf.setAddECPointFormatExtension(true);
        testConf.setAddSignatureAndHashAlgorithmsExtension(true);
        testConf.setAddRenegotiationInfoExtension(false);
        testConf.setUseFreshRandom(false);
        testConf.setDefaultClientRandom(clientRandom);
        testConf.setStopActionsAfterFatal(true);
        testConf.setDefaultClientSessionId(intToByteArray(1));

        testConf.setQuickReceive(true);
        testConf.setEarlyStop(true);

        List<NamedGroup> supportedGroups = new LinkedList<>();
        for (NamedGroup group : latestReport.getSupportedNamedGroups()) {
            if (!group.name().contains("FFDHE") && !group.name().contains(NamedGroup.ECDH_X25519.name())
                    && !group.name().contains(NamedGroup.ECDH_X448.name())) {
                supportedGroups.add(group);
            }
        }
        testConf.setDefaultClientNamedGroups(supportedGroups);

        return testConf;
    }

    private Config generateTls13Config(byte[] clientRandom) {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        List<NamedGroup> tls13Groups = new LinkedList<>();
        for (NamedGroup group : NamedGroup.values()) {
            if (group.isTls13() && !group.name().contains("FFDHE")
                    && !group.name().contains(NamedGroup.ECDH_X25519.name())
                    && !group.name().contains(NamedGroup.ECDH_X448.name())) {
                tls13Groups.add(group);
            }
        }
        tlsConfig.setDefaultClientNamedGroups(tls13Groups);
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setUseFreshRandom(false);
        tlsConfig.setDefaultClientRandom(clientRandom);

        List<SignatureAndHashAlgorithm> algos = new LinkedList<>();
        algos.add(SignatureAndHashAlgorithm.RSA_SHA256);
        algos.add(SignatureAndHashAlgorithm.RSA_SHA384);
        algos.add(SignatureAndHashAlgorithm.RSA_SHA512);
        algos.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        algos.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        algos.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA384);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA512);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384);
        algos.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512);

        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(algos);
        return tlsConfig;
    }

    private void collectServerRandomTls13(int numberOfHandshakes, int clientRandomInit) {
        CipherSuite[] supportedSuites = null;
        for (VersionSuiteListPair versionSuitePair : latestReport.getVersionSuitePairs()) {
            if (versionSuitePair.getVersion().isTLS13()) {
                supportedSuites = new CipherSuite[versionSuitePair.getCiphersuiteList().size()];
                versionSuitePair.getCiphersuiteList().toArray(supportedSuites);
            }
        }
        byte[] serverRandom = null;
        byte[] serverExtendedRandom = null;

        boolean supportsExtendedRandom = latestReport.getSupportedExtensions().contains(ExtensionType.EXTENDED_RANDOM);

        for (int i = 0; i < numberOfHandshakes; i++) {
            Config serverHelloConfig = generateTls13Config(intToByteArray(clientRandomInit + i));

            if (supportsExtendedRandom) {
                LOGGER.warn("Extended Random Supported!");
                serverHelloConfig.setParseKeyShareOld(false);
                serverHelloConfig.setAddExtendedRandomExtension(true);
            }

            serverHelloConfig.setEnforceSettings(true);

            serverHelloConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);

            State test_state = new State(serverHelloConfig);
            executeState(test_state);

            serverRandom = test_state.getTlsContext().getServerRandom();
            serverExtendedRandom = test_state.getTlsContext().getServerExtendedRandom();
            byte[] completeServerRandom = ArrayConverter.concatenate(serverRandom, serverExtendedRandom);
            if (!(completeServerRandom.length == 0)) {
                extractedRandomList.add(new ComparableByteArray(completeServerRandom));
            }

            // SessionIDs are mirrored from client SessionID in TLS 1.3, so we
            // dont bother with them here.

            LOGGER.warn("===========================================================================================");
            LOGGER.warn(test_state.getWorkflowTrace());
            LOGGER.warn(test_state.getTlsContext().getSelectedProtocolVersion());
            LOGGER.warn(test_state.getTlsContext().getSelectedCipherSuite());
            LOGGER.warn(ArrayConverter.bytesToHexString(test_state.getTlsContext().getServerSessionId()));
            LOGGER.warn(ArrayConverter.bytesToHexString(test_state.getTlsContext().getClientRandom()));
            LOGGER.warn(ArrayConverter.bytesToHexString(test_state.getTlsContext().getServerRandom()));
            LOGGER.warn("===========================================================================================");
        }

    }

    private void collectServerRandom(int numberOfHandshakes, int clientRandomInit) {
        // Use preferred Ciphersuites if supported
        List<CipherSuite> serverHelloCollectSuites = new LinkedList<>();
        CipherSuite[] supportedSuites = new CipherSuite[latestReport.getCipherSuites().toArray().length];
        supportedSuites = latestReport.getCipherSuites().toArray(supportedSuites);
        if (latestReport.getResult(AnalyzedProperty.SUPPORTS_RSA) == TestResult.TRUE) {
            for (CipherSuite cipherSuite : supportedSuites) {
                if (cipherSuite.name().contains("TLS_RSA")) {
                    serverHelloCollectSuites.add(cipherSuite);
                }
            }
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.TRUE) {
            for (CipherSuite cipherSuite : supportedSuites) {
                if (cipherSuite.name().contains("TLS_DH")) {
                    serverHelloCollectSuites.add(cipherSuite);
                }
            }
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) == TestResult.TRUE) {
            for (CipherSuite cipherSuite : supportedSuites) {
                if (cipherSuite.name().contains("TLS_ECDH")) {
                    serverHelloCollectSuites.add(cipherSuite);
                }
            }
        }

        boolean supportsExtendedRandom = latestReport.getSupportedExtensions().contains(ExtensionType.EXTENDED_RANDOM);

        for (int i = 0; i < numberOfHandshakes; i++) {
            Config serverHelloConfig = generateTestConfig(intToByteArray(clientRandomInit + i));
            byte[] serverRandom = null;
            byte[] serverExtendedRandom = null;
            byte[] sessionID = null;

            if (supportsExtendedRandom) {
                LOGGER.warn("Extended Random Supported!");
                serverHelloConfig.setParseKeyShareOld(false);
                serverHelloConfig.setAddExtendedRandomExtension(true);

            }
            serverHelloConfig.setHighestProtocolVersion(highestVersion);
            serverHelloConfig.setSupportedVersions(highestVersion);
            if (!serverHelloCollectSuites.isEmpty()) {
                serverHelloConfig.setDefaultClientSupportedCiphersuites(serverHelloCollectSuites);
            } else {
                // Fallback to supported Suites
                serverHelloConfig.setDefaultClientSupportedCiphersuites(supportedSuites);
            }

            serverHelloConfig.setEnforceSettings(true);

            serverHelloConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);

            State test_state = new State(serverHelloConfig);
            executeState(test_state);

            serverRandom = test_state.getTlsContext().getServerRandom();
            serverExtendedRandom = test_state.getTlsContext().getServerExtendedRandom();
            byte[] completeServerRandom = ArrayConverter.concatenate(serverRandom, serverExtendedRandom);
            if (!(completeServerRandom.length == 0)) {
                extractedRandomList.add(new ComparableByteArray(completeServerRandom));
            }

            sessionID = test_state.getTlsContext().getServerSessionId();
            if (!(sessionID.length == 0)) {
                extractedSessionIDList.add(new ComparableByteArray(sessionID));
            }

            LOGGER.warn("===========================================================================================");
            LOGGER.warn(test_state.getWorkflowTrace());
            LOGGER.warn(test_state.getTlsContext().getSelectedProtocolVersion());
            LOGGER.warn(test_state.getTlsContext().getSelectedCipherSuite());
            LOGGER.warn(ArrayConverter.bytesToHexString(test_state.getTlsContext().getClientRandom()));
            LOGGER.warn(ArrayConverter.bytesToHexString(test_state.getTlsContext().getServerRandom()));
            LOGGER.warn("===========================================================================================");
        }
    }

    private void collectIV(int numberOfBlocks, int clientRandomInit) {
        // Collect IV
        // Here it is not important which ciphersuite we use for key-exchange,
        // only important thing is maximum
        // block size of encrypted blocks.
        int handshakeCounter = 1;
        CipherSuite[] supportedSuites = new CipherSuite[latestReport.getCipherSuites().toArray().length];
        supportedSuites = latestReport.getCipherSuites().toArray(supportedSuites);
        List<CipherSuite> cbcSuites = new LinkedList<>();
        List<CipherSuite> shortCbcSuites = new LinkedList<>();
        List<CipherSuite> selectedSuites = new LinkedList<>();
        for (CipherSuite suite : supportedSuites) {
            if (suite.name().contains("CBC")) {
                if (suite.name().contains("256_CBC")) {
                    cbcSuites.add(suite);
                } else {
                    shortCbcSuites.add(suite);
                }
            }
        }

        if (cbcSuites.isEmpty()) {
            if (shortCbcSuites.isEmpty()) {
                LOGGER.warn("NO CBC SUITES! Falling back to collect more Server Randoms instead ...");
                // Assume we would collect 16 Bytes per record
                int numberOfHandshakes = (numberOfBlocks / (SERVER_RANDOM_SIZE / IV_SIZE));
                if (highestVersion == ProtocolVersion.TLS13) {
                    collectServerRandomTls13(numberOfHandshakes, clientRandomInit + handshakeCounter);
                } else {
                    collectServerRandom(numberOfHandshakes, clientRandomInit + handshakeCounter);
                }
                return;
            } else {
                selectedSuites = shortCbcSuites;
            }
        } else {
            selectedSuites = cbcSuites;
        }

        // Collect IV when CBC Suites are available
        Config iVCollectConfig = generateTestConfig(intToByteArray(clientRandomInit + handshakeCounter));

        iVCollectConfig.setDefaultClientSupportedCiphersuites(selectedSuites);

        State collectState = generateOpenConnection(iVCollectConfig);
        if (collectState == null) {
            LOGGER.warn("Can't collect IVs.");
            return;
        }

        LOGGER.warn(collectState.getWorkflowTrace());
        LOGGER.warn(collectState.getTlsContext().getSelectedProtocolVersion());
        LOGGER.warn(collectState.getTlsContext().getSelectedCipherSuite());
        LOGGER.warn("IS EARLY STOP: " + collectState.getTlsContext().getConfig().isEarlyStop());

        SendMessageHelper sendMessageHelper = new SendMessageHelper();
        ReceiveMessageHelper receiveMessageHelper = new ReceiveMessageHelper();

        HttpsRequestMessage httpGet = new HttpsRequestMessage(iVCollectConfig);
        List<HttpsHeader> header = new LinkedList<>();
        header.add(new HostHeader());
        httpGet.setHeader(header);
        // HTTP HEAD REQUEST --> Currently HTTP GET better because we get more
        // blocks per request
        // ModifiableString modifiableString = new ModifiableString();
        // modifiableString.setModification(StringModificationFactory.explicitValue("HEAD"));
        // When possible use this :
        // httpGet.setRequestType(Modifiable.explicit("HEAD"));
        // httpGet.setRequestType(modifiableString);
        List<AbstractRecord> records = new ArrayList<>();
        List<ProtocolMessage> messages = new ArrayList<>();
        MessageActionResult result = null;
        TlsContext tlsContext = collectState.getTlsContext();
        // tlsContext.getTransportHandler().setTimeout(10000);

        int receiveFailures = 0;
        int newConnectionCounter = 0;
        int receivedBlocksCounter = 0;
        while (receivedBlocksCounter < numberOfBlocks) {

            if (receiveFailures > 2) {
                LOGGER.warn("Creating new connection for IV Collection.");
                if (newConnectionCounter > 3) {
                    LOGGER.warn("Too many new Connections without new messages. Quitting.");
                    break;
                }
                handshakeCounter++;
                iVCollectConfig = generateTestConfig(intToByteArray(clientRandomInit + handshakeCounter));
                iVCollectConfig.setDefaultClientSupportedCiphersuites(selectedSuites);
                collectState = generateOpenConnection(iVCollectConfig);
                try {
                    if ((collectState == null) || collectState.getTlsContext().getTransportHandler().isClosed()) {
                        LOGGER.warn("Trying again for new Connection.");
                        collectState = generateOpenConnection(iVCollectConfig);
                        if ((collectState == null) || collectState.getTlsContext().getTransportHandler().isClosed()) {
                            LOGGER.warn("No new Connections possible. Stopping IV Collection.");
                            break;
                        }
                    }
                    tlsContext = collectState.getTlsContext();
                    newConnectionCounter++;
                    receiveFailures = 0;
                } catch (IOException e) {
                    LOGGER.warn("Could not create new connection.");
                    e.printStackTrace();
                    break;
                }

            }

            messages = new ArrayList<>();
            messages.add(httpGet);
            records = null;
            result = null;
            try {
                sendMessageHelper.sendMessages(messages, records, tlsContext);
            } catch (IOException e) {
                LOGGER.warn("Encountered Problems sending Requests. Socket closed?");
                e.printStackTrace();
                receiveFailures++;
                continue;
            }

            result = receiveMessageHelper.receiveMessagesTill(new ApplicationMessage(iVCollectConfig), tlsContext);
            messages = new ArrayList<>(result.getMessageList());
            records = new ArrayList<>(result.getRecordList());

            if (!(messages.size() == 0)
                    && messages.get(0).getProtocolMessageType() == ProtocolMessageType.APPLICATION_DATA) {
                int receivedBlocks = 0;
                for (AbstractRecord receivedRecords : records) {
                    ModifiableByteArray extractedIV = ((Record) receivedRecords).getComputations()
                            .getCbcInitialisationVector();
                    if (!(extractedIV == null)) {
                        // Set newConnectionCounter to 0 if we received valid
                        // IVs after creating a new
                        // connection to mitigate the problem of successfully
                        // creating new
                        // connections but not receiving any messages.
                        if (!(newConnectionCounter == 0)) {
                            newConnectionCounter = 0;
                        }
                        receivedBlocks++;
                        extractedIVList.add(new ComparableByteArray(extractedIV.getOriginalValue()));
                        LOGGER.warn("Received IV: " + ArrayConverter.bytesToHexString(extractedIV.getOriginalValue()));
                    }

                }
                receivedBlocksCounter = receivedBlocksCounter + receivedBlocks;
                LOGGER.warn("Currently Received Blocks : " + receivedBlocksCounter);
            } else {
                LOGGER.warn("Did not receive any messages.");
                receiveFailures++;
            }

        }

        try {
            tlsContext.getTransportHandler().closeConnection();
        } catch (IOException e) {
            LOGGER.warn("Could not close TransportHandler.");
            e.printStackTrace();
        }

        if (receivedBlocksCounter < numberOfBlocks) {
            // This means there were problems while collecting IV.
            // Collecting remaining bytes as server randoms.
            int numberOfHandshakes = (numberOfBlocks - receivedBlocksCounter) / (SERVER_RANDOM_SIZE / IV_SIZE);
            if (highestVersion == ProtocolVersion.TLS13) {
                collectServerRandomTls13(numberOfHandshakes, clientRandomInit + handshakeCounter);
            } else {
                collectServerRandom(numberOfHandshakes, clientRandomInit + handshakeCounter);
            }

        }

    }

    /**
     * Checks if the Host utilities Unix time for Server Randoms
     * 
     * @return
     */
    private boolean checkForUnixTime() {
        boolean usesUnixTime = false;
        Config unixConfig;
        int matchCounter = 0;

        if (highestVersion == ProtocolVersion.TLS13) {
            unixConfig = generateTls13Config(intToByteArray(9999));
        } else {
            unixConfig = generateTestConfig(intToByteArray(9999));
            CipherSuite[] supportedSuites = new CipherSuite[latestReport.getCipherSuites().toArray().length];
            supportedSuites = latestReport.getCipherSuites().toArray(supportedSuites);
            unixConfig.setDefaultClientSupportedCiphersuites(supportedSuites);
        }

        unixConfig.setEnforceSettings(true);
        unixConfig.setHighestProtocolVersion(highestVersion);
        unixConfig.setSupportedVersions(highestVersion);
        unixConfig.setUseFreshRandom(true);

        unixConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);

        for (int i = 0; i < 10; i++) {
            int currentUnixTime = (int) (System.currentTimeMillis() / 1000);
            int serverUnixTime = 0;
            LOGGER.warn("UNIX_TIME_STAMP_TEST : Current UnixTimeStamp : " + currentUnixTime);
            // currentUnixTime = new byte[]{
            // (byte) (currentUnixTime >> 24),
            // (byte) (currentUnixTime >> 16),
            // (byte) (currentUnixTime >> 8),
            // (byte) currentUnixTime
            // };

            State unixState = new State(unixConfig);
            executeState(unixState);

            LOGGER.warn("UNIX_TIME_STAMP_TEST: SERVER RANDOM: "
                    + ArrayConverter.bytesToHexString(unixState.getTlsContext().getServerRandom()));
            byte[] serverRandom = unixState.getTlsContext().getServerRandom();
            if (!(serverRandom == null)) {
                byte[] unixTimeStamp = new byte[4];
                for (int j = 0; j < 4; j++) {
                    unixTimeStamp[j] = serverRandom[j];
                }
                serverUnixTime = java.nio.ByteBuffer.wrap(unixTimeStamp).order(ByteOrder.BIG_ENDIAN).getInt();
                if (currentUnixTime - UNIX_TIME_ALLOWED_DEVIATION < serverUnixTime) {
                    if (currentUnixTime + UNIX_TIME_ALLOWED_DEVIATION > serverUnixTime) {
                        matchCounter++;
                    }
                }
            }
        }

        LOGGER.warn("MATCHCOUNTER: " + matchCounter);
        if (matchCounter == 10) {
            LOGGER.warn("ServerRandom utilizes UnixTimestamps.");
            usesUnixTime = true;
        } else {
            LOGGER.warn("No UnixTimestamps detected.");
        }

        return usesUnixTime;
    }

    private State generateOpenConnection(Config config) {
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
        config.setWorkflowExecutorShouldClose(false);
        config.setEarlyStop(true);
        config.setQuickReceive(true);
        config.setEnforceSettings(true);
        State state = new State(config);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                WorkflowExecutorType.DEFAULT, state);
        try {
            workflowExecutor.executeWorkflow();
        } catch (TransportHandlerConnectException ex) {
            ex.printStackTrace();
            LOGGER.warn("Could not open new Connection.");
            return null;
        }
        return state;
    }

    private byte[] intToByteArray(int number) {
        BigInteger bigNum = BigInteger.valueOf(number);
        byte[] bigNumArray = bigNum.toByteArray();
        byte[] output = new byte[32];
        System.arraycopy(bigNumArray, 0, output, 0, bigNumArray.length);
        return output;
    }

}
