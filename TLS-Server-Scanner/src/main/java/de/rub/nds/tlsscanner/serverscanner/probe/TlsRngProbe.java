/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.exceptions.TransportHandlerConnectException;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.header.HostHeader;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.TlsRngResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * A probe which samples random material from the target host using ServerHello
 * randoms, SessionIDs and IVs.
 *
 * @author Dennis Ziebart - dziebart@mail.uni-paderborn.de
 */
public class TlsRngProbe extends TlsProbe {

    private final int SERVER_RANDOM_SIZE = 32;
    private final int IV_SIZE = 16;
    // Fixed Amount of required Handshakes
    private final int NUMBER_OF_HANDSHAKES = 600;
    // First ClientHello random value
    private final int CLIENT_RANDOM_START = 1;
    // Amount of IV Blocks required to collect
    private final int IV_BLOCKS = 4000;
    private final int IV_MAXIMUM_RECEIVE_FAILURES = 2;
    private final int IV_MAXIMUM_CONNECTION_FAILURES = 3;
    // How much the time is allowed to deviate between two handshakes when
    // viewed using UNIX time prefix
    private final int UNIX_TIME_ALLOWED_DEVIATION = 500;
    private final int TLS_CONNECTIONS_UPPER_LIMIT = 1000;
    // Amount of retries allowed when failing to receive ServerHello messages in
    // the Unix Time test
    private final int UNIX_TIME_CONNECTIONS = 5;
    // How many of the 3 ServerHello randoms should pass the Unix Time test at
    // minimum.
    private final int MINIMUM_MATCH_COUNTER = 2;

    private ProtocolVersion highestVersion;
    private SiteReport latestReport;
    private LinkedList<ComparableByteArray> extractedIVList;
    private LinkedList<ComparableByteArray> extractedRandomList;
    private LinkedList<ComparableByteArray> extractedSessionIDList;
    private boolean prematureStop = false;

    private boolean usesUnixTime = false;
    // Maximum amount of TLS Handshakes allowed
    private int tlsConnectionCounter = 0;

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
            LOGGER.debug("SETTING HIGHEST VERSION TO TLS13");
            highestVersion = ProtocolVersion.TLS13;
            usesUnixTime = checkForUnixTime();
            collectServerRandomTls13(NUMBER_OF_HANDSHAKES, CLIENT_RANDOM_START);
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.TRUE) {
            LOGGER.debug("SETTING HIGHEST VERSION TO TLS12");
            highestVersion = ProtocolVersion.TLS12;
            usesUnixTime = checkForUnixTime();
            collectServerRandom(NUMBER_OF_HANDSHAKES, CLIENT_RANDOM_START);
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.TRUE) {
            LOGGER.debug("SETTING HIGHEST VERSION TO TLS11");
            highestVersion = ProtocolVersion.TLS11;
            usesUnixTime = checkForUnixTime();
            collectServerRandom(NUMBER_OF_HANDSHAKES, CLIENT_RANDOM_START);
        } else if (latestReport.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.TRUE) {
            LOGGER.debug("SETTING HIGHEST VERSION TO TLS10");
            highestVersion = ProtocolVersion.TLS10;
            usesUnixTime = checkForUnixTime();
            collectServerRandom(NUMBER_OF_HANDSHAKES, CLIENT_RANDOM_START);
        }

        // ////////////////////////////////////////////////////////////////////////////////////////////////////
        // Set ClientHello random to last-value sent + 50 to be safe
        collectIV(IV_BLOCKS, CLIENT_RANDOM_START + NUMBER_OF_HANDSHAKES + 50);
        // /////////////////////////////////////////////////////////////////////////////////////////////////////

        // If we reached this point we collected some amount of data.
        // TlsRngAfterProbe will determine if this
        // is enough.
        boolean successfulHandshake = true;

        TlsRngResult rng_extract = new TlsRngResult(successfulHandshake, extractedIVList, extractedRandomList,
                extractedSessionIDList, usesUnixTime, prematureStop);

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
                || report.getResult(AnalyzedProperty.GROUPS_DEPEND_ON_CIPHER) == TestResult.NOT_TESTED_YET) {
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
        return new TlsRngResult(false, null, null, null, false, false);
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    /**
     * Generates a TLS-Config used to scan for random data. This method is
     * employed as the Handshakes conducted in this probe share numerous
     * parameters, requiring it only to invoke this method before creating a new
     * connection instead of defining a new Config for every new connection.
     *
     * @param clientRandom The random of the ClientHello to be sent
     * @return TLS-Config ready for establishing a new connection
     */
    private Config generateBaseConfig() {
        Config config = getScannerConfig().createConfig();

        config.setEnforceSettings(false);
        config.setAddServerNameIndicationExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddECPointFormatExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddRenegotiationInfoExtension(false);
        config.setUseFreshRandom(false);
        byte[] random = new byte[32];
        RandomHelper.getRandom().nextBytes(random);
        config.setDefaultClientRandom(random);
        config.setStopActionsAfterFatal(true);
        config.setAddServerNameIndicationExtension(true);
        config.setDefaultClientSessionId(new byte[0]);

        config.setQuickReceive(true);
        config.setEarlyStop(true);

        List<NamedGroup> supportedGroups = new LinkedList<>();
        for (NamedGroup group : latestReport.getSupportedNamedGroups()) {
            if (!group.name().contains("FFDHE") && !group.name().contains(NamedGroup.ECDH_X25519.name())
                    && !group.name().contains(NamedGroup.ECDH_X448.name())) {
                supportedGroups.add(group);
            }
        }
        if (!(supportedGroups.size() == 0)) {
            config.setDefaultClientNamedGroups(supportedGroups);
        }

        return config;
    }

    /**
     * Same as generateTestConfig but adapted for TLS 1.3 Handshakes.
     *
     * @return TLS-Config ready for establishing a new connection
     */
    private Config generateTls13BaseConfig() {
        Config config = getScannerConfig().createConfig();
        config.setQuickReceive(true);
        config.setDefaultClientSupportedCipherSuites(CipherSuite.getImplementedTls13CipherSuites());
        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setSupportedVersions(ProtocolVersion.TLS13);
        config.setEnforceSettings(false);
        config.setEarlyStop(true);
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        config.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        config.setAddServerNameIndicationExtension(true);
        config.setUseFreshRandom(false);
        byte[] random = new byte[32];
        RandomHelper.getRandom().nextBytes(random);
        config.setDefaultClientRandom(random);

        List<SignatureAndHashAlgorithm> algos = SignatureAndHashAlgorithm.getTls13SignatureAndHashAlgorithms();
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(algos);

        return config;
    }

    /**
     * Same as collectServerRandom but adapted for TLS 1.3. This limits the
     * number of cipher suites available and the messages to be sent.
     *
     * @param numberOfHandshakes The amount of handshakes this method should
     * conduct.
     * @param clientRandomInit The first clientHello random to be sent,
     * incrementing this value for each Handshake.
     */
    private void collectServerRandomTls13(int numberOfHandshakes, int clientRandomInit) {
        CipherSuite[] supportedSuites = null;
        for (VersionSuiteListPair versionSuitePair : latestReport.getVersionSuitePairs()) {
            if (versionSuitePair.getVersion().isTLS13()) {
                supportedSuites = new CipherSuite[versionSuitePair.getCipherSuiteList().size()];
                versionSuitePair.getCipherSuiteList().toArray(supportedSuites);
            }
        }

        boolean supportsExtendedRandom = latestReport.getSupportedExtensions().contains(ExtensionType.EXTENDED_RANDOM);

        if (usesUnixTime) {
            // Convert required amount of Handshakes to number of handshakes
            // when we only get 28 Bytes.
            numberOfHandshakes = (int) Math.ceil((numberOfHandshakes * SERVER_RANDOM_SIZE)
                    / (double) (HandshakeByteLength.RANDOM - HandshakeByteLength.UNIX_TIME));
        }

        for (int i = 0; i < numberOfHandshakes; i++) {
            Config serverHelloConfig = generateTls13BaseConfig();

            if (supportsExtendedRandom) {
                LOGGER.debug("Extended Random Supported!");
                serverHelloConfig.setAddExtendedRandomExtension(true);
            }

            serverHelloConfig.setEnforceSettings(true);

            serverHelloConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);

            if (tlsConnectionCounter >= TLS_CONNECTIONS_UPPER_LIMIT) {
                LOGGER.debug("Reached Hard Upper Limit for maximum allowed Tls Connections. Aborting.");
                prematureStop = true;
                return;
            }

            State test_state = new State(serverHelloConfig);
            executeState(test_state);
            tlsConnectionCounter++;

            LOGGER.debug("=========================================================================================");

            // Extended Random is automatically appended by a Handler of
            // TLS-Attacker
            byte[] completeServerRandom = test_state.getTlsContext().getServerRandom();

            if (!(completeServerRandom == null) && !(completeServerRandom.length == 0)) {
                if (usesUnixTime) {
                    byte[] timeLessServerRandom = Arrays.copyOfRange(completeServerRandom,
                            HandshakeByteLength.UNIX_TIME, completeServerRandom.length);
                    LOGGER.debug("TIMELESS SERVER RANDOM : " + ArrayConverter.bytesToHexString(timeLessServerRandom));
                    extractedRandomList.add(new ComparableByteArray(timeLessServerRandom));
                } else {
                    extractedRandomList.add(new ComparableByteArray(completeServerRandom));
                }
            }

            // SessionIDs are mirrored from client SessionID in TLS 1.3, so we
            // dont bother with them here.
            LOGGER.debug(ArrayConverter.bytesToHexString(test_state.getTlsContext().getClientRandom()));
            LOGGER.debug(ArrayConverter.bytesToHexString(test_state.getTlsContext().getServerRandom()));
            LOGGER.debug(test_state.getTlsContext().getSelectedProtocolVersion());
            LOGGER.debug(test_state.getTlsContext().getSelectedCipherSuite());
            LOGGER.debug(test_state.getWorkflowTrace());
            LOGGER.debug("=========================================================================================");
        }

    }

    /**
     * Method employed to collect SessionIDs and ServerHello randoms. This
     * method will first select the appropriate cipher suite for maximum
     * randomness "yield". Depending on if the host supports ExtendedRandom or
     * uses Unix Time prefixes, the resulting randomness data will be extracted
     * and saved to two list of byteArrays representing the SessionIDs and
     * ServerHello randoms.
     *
     * @param numberOfHandshakes The amount of handshakes this method should
     * conduct.
     * @param clientRandomInit The first clientHello random to be sent,
     * incrementing this value for each Handshake.
     */
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

        if (usesUnixTime) {
            // Convert required amount of Handshakes to number of handshakes
            // when we only get 28 Bytes.
            numberOfHandshakes = (int) Math.ceil((numberOfHandshakes * SERVER_RANDOM_SIZE)
                    / (double) (HandshakeByteLength.RANDOM - HandshakeByteLength.UNIX_TIME));
        }

        for (int i = 0; i < numberOfHandshakes; i++) {
            Config serverHelloConfig = generateBaseConfig();
            byte[] sessionID = null;

            if (supportsExtendedRandom) {
                LOGGER.debug("Extended Random Supported!");
                serverHelloConfig.setAddExtendedRandomExtension(true);

            }
            serverHelloConfig.setHighestProtocolVersion(highestVersion);
            serverHelloConfig.setSupportedVersions(highestVersion);
            if (!serverHelloCollectSuites.isEmpty()) {
                serverHelloConfig.setDefaultClientSupportedCipherSuites(serverHelloCollectSuites);
            } else {
                // Fallback to supported Suites
                serverHelloConfig.setDefaultClientSupportedCipherSuites(supportedSuites);
            }

            serverHelloConfig.setEnforceSettings(true);

            serverHelloConfig.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);

            if (tlsConnectionCounter >= TLS_CONNECTIONS_UPPER_LIMIT) {
                LOGGER.debug("Reached Hard Upper Limit for maximum allowed Tls Connections. Aborting.");
                prematureStop = true;
                return;
            }

            State test_state = new State(serverHelloConfig);
            executeState(test_state);
            tlsConnectionCounter++;

            LOGGER.debug("========================================================================================");

            // Extended Random is automatically appended by a Handler of
            // TLS-Attacker
            byte[] completeServerRandom = test_state.getTlsContext().getServerRandom();

            LOGGER.debug(
                    "CLIENT RANDOM: " + ArrayConverter.bytesToHexString(test_state.getTlsContext().getClientRandom()));
            LOGGER.debug(
                    "SERVER RANDOM: " + ArrayConverter.bytesToHexString(test_state.getTlsContext().getServerRandom()));

            if (!(completeServerRandom == null) && !(completeServerRandom.length == 0)) {
                if (usesUnixTime) {
                    byte[] timeLessServerRandom = Arrays.copyOfRange(completeServerRandom,
                            HandshakeByteLength.UNIX_TIME, completeServerRandom.length);
                    LOGGER.debug("TIMELESS SERVER RANDOM : " + ArrayConverter.bytesToHexString(timeLessServerRandom));
                    extractedRandomList.add(new ComparableByteArray(timeLessServerRandom));
                } else {
                    extractedRandomList.add(new ComparableByteArray(completeServerRandom));
                }
            }

            sessionID = test_state.getTlsContext().getServerSessionId();
            if (!(sessionID == null) && !(sessionID.length == 0)) {
                extractedSessionIDList.add(new ComparableByteArray(sessionID));
            }

            LOGGER.debug(test_state.getTlsContext().getSelectedProtocolVersion());
            LOGGER.debug(test_state.getTlsContext().getSelectedCipherSuite());
            LOGGER.debug(test_state.getWorkflowTrace());
            LOGGER.debug("========================================================================================");
        }
    }

    /**
     * Method employed to collect the numberOfBlocks amount of IV blocks
     * (assuming the optimum of 16 bytes per block). The most appropriate cipher
     * suite is determined and a new connection is opened using this cipher
     * suite. The resulting connection is then utilized to collect IV blocks by
     * sending encrypted HTTP GETs to the Server, collecting the IV blocks used
     * to encrypt the responses. Multiple schemes are employed to ensure that
     * the required amount of data is collected, including creating new
     * connections, stopping after too many failures and a fallback mechanism to
     * collect more ServerHello randoms when the collection of IVs is
     * prematurely stopped.
     *
     * @param numberOfBlocks amount of blocks required to collect
     * @param clientRandomInit the initial ClientHello random sent to the Server
     * when opening a new Connection.
     */
    private void collectIV(int numberOfBlocks, int clientRandomInit) {
        // Collect IV
        // Here it is not important which ciphersuite we use for key-exchange,
        // only important thing is maximum
        // block size of encrypted blocks.
        int handshakeCounter = 1;
        CipherSuite[] supportedSuites = new CipherSuite[latestReport.getCipherSuites().toArray().length];
        supportedSuites = latestReport.getCipherSuites().toArray(supportedSuites);
        List<CipherSuite> cbcSuites = new LinkedList<>();
        for (CipherSuite suite : supportedSuites) {
            if (suite.name().contains("CBC")) {
                cbcSuites.add(suite);
            }
        }

        if (!cbcSuites.isEmpty()) {
            // Collect IV when CBC Suites are available
            Config iVCollectConfig = generateBaseConfig();

            iVCollectConfig.setDefaultClientSupportedCipherSuites(cbcSuites);

            State collectState = generateOpenConnection(iVCollectConfig);
            if (collectState == null) {
                LOGGER.debug("Can't collect IVs.");
                return;
            }

            LOGGER.debug(collectState.getWorkflowTrace());
            LOGGER.debug(collectState.getTlsContext().getSelectedProtocolVersion());
            LOGGER.debug(collectState.getTlsContext().getSelectedCipherSuite());
            LOGGER.debug("IS EARLY STOP: " + collectState.getTlsContext().getConfig().isEarlyStop());

            SendMessageHelper sendMessageHelper = new SendMessageHelper();
            ReceiveMessageHelper receiveMessageHelper = new ReceiveMessageHelper();

            HttpsRequestMessage httpGet = new HttpsRequestMessage(iVCollectConfig);
            List<HttpsHeader> header = new LinkedList<>();
            header.add(new HostHeader());
            httpGet.setHeader(header);
            List<AbstractRecord> records = new ArrayList<>();
            List<ProtocolMessage> messages = new ArrayList<>();
            MessageActionResult result = null;
            TlsContext tlsContext = collectState.getTlsContext();
            // tlsContext.getTransportHandler().setTimeout(10000);

            int receiveFailures = 0;
            int newConnectionCounter = 0;
            int receivedBlocksCounter = 0;
            while (receivedBlocksCounter < numberOfBlocks) {

                if (receiveFailures > IV_MAXIMUM_RECEIVE_FAILURES) {
                    LOGGER.debug("Creating new connection for IV Collection.");
                    if (newConnectionCounter > IV_MAXIMUM_CONNECTION_FAILURES) {
                        LOGGER.debug("Too many new Connections without new messages. Quitting.");
                        break;
                    }
                    handshakeCounter++;
                    iVCollectConfig = generateBaseConfig();
                    iVCollectConfig.setDefaultClientSupportedCipherSuites(cbcSuites);
                    if (tlsConnectionCounter >= TLS_CONNECTIONS_UPPER_LIMIT) {
                        LOGGER.debug("Reached Hard Upper Limit for maximum allowed Tls Connections. Aborting.");
                        prematureStop = true;
                        return;
                    }
                    collectState = generateOpenConnection(iVCollectConfig);
                    try {
                        if ((collectState == null) || collectState.getTlsContext().getTransportHandler().isClosed()) {
                            LOGGER.debug("Trying again for new Connection.");
                            if (tlsConnectionCounter >= TLS_CONNECTIONS_UPPER_LIMIT) {
                                LOGGER.debug("Reached Hard Upper Limit for maximum allowed Tls Connections. Aborting.");
                                prematureStop = true;
                                return;
                            }
                            collectState = generateOpenConnection(iVCollectConfig);
                            if ((collectState == null) || collectState.getTlsContext().getTransportHandler().isClosed()) {
                                LOGGER.debug("No new Connections possible. Stopping IV Collection.");
                                break;
                            }
                        }
                        tlsContext = collectState.getTlsContext();
                        newConnectionCounter++;
                        receiveFailures = 0;
                    } catch (IOException e) {
                        LOGGER.debug("Could not create new connection.", e);
                        break;
                    }

                }

                messages = new ArrayList<>();
                messages.add(httpGet);
                records = null;
                // Resetting result to null ensures we do not consider old results
                result = null;
                try {
                    sendMessageHelper.sendMessages(messages, records, tlsContext);
                } catch (IOException e) {
                    LOGGER.debug("Encountered Problems sending Requests. Socket closed?", e);
                    receiveFailures++;
                    continue;
                }

                result = receiveMessageHelper.receiveMessagesTill(new ApplicationMessage(iVCollectConfig), tlsContext);
                messages = new ArrayList<>(result.getMessageList());
                records = new ArrayList<>(result.getRecordList());

                if (!messages.isEmpty() && messages.get(0) instanceof TlsMessage
                        && ((TlsMessage) (messages.get(0))).getProtocolMessageType() == ProtocolMessageType.APPLICATION_DATA) {
                    int receivedBlocks = 0;
                    for (AbstractRecord receivedRecords : records) {
                        ModifiableByteArray extractedIV
                                = ((Record) receivedRecords).getComputations().getCbcInitialisationVector();
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
                            LOGGER.debug("Received IV: " + ArrayConverter.bytesToHexString(extractedIV.getOriginalValue()));
                        }

                    }
                    receivedBlocksCounter = receivedBlocksCounter + receivedBlocks;
                    LOGGER.debug("Currently Received Blocks : " + receivedBlocksCounter);
                } else {
                    LOGGER.debug("Did not receive any messages.");
                    receiveFailures++;
                }

            }

            try {
                tlsContext.getTransportHandler().closeConnection();
            } catch (IOException e) {
                LOGGER.debug("Could not close TransportHandler.", e);
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
        } else {
            LOGGER.debug("Server does not support CBC. Not collecting CBC IV's");
        }
    }

    /**
     * Checks if the Host utilities Unix time or similar counters for Server
     * Randoms.
     *
     * @return TRUE if the server is probably using a counter in its server
     * random.
     */
    private boolean checkForUnixTime() {
        Config config;
        int matchCounter = 0;

        if (highestVersion == ProtocolVersion.TLS13) {
            config = generateTls13BaseConfig();
        } else {
            config = generateBaseConfig();
        }

        config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);

        Integer lastUnixTime = null;
        Integer serverUnixTime = null;

        for (int i = 0; i < UNIX_TIME_CONNECTIONS; i++) {

            State state = new State(config);
            long startTime = System.currentTimeMillis();
            executeState(state);
            long endTime = System.currentTimeMillis();

            // current time is in milliseconds
            long duration = (endTime - startTime) / 1000;

            byte[] serverRandom = state.getTlsContext().getServerRandom();
            LOGGER.debug("Duration: " + duration);
            if (lastUnixTime != null) {
                if (serverRandom != null) {
                    byte[] unixTimeStamp = new byte[4];
                    System.arraycopy(serverRandom, 0, unixTimeStamp, 0, HandshakeByteLength.UNIX_TIME);
                    serverUnixTime = ArrayConverter.bytesToInt(unixTimeStamp);
                    LOGGER.debug("Previous Time: " + lastUnixTime);
                    LOGGER.debug("Current Time: " + serverUnixTime);
                    if (lastUnixTime - (UNIX_TIME_ALLOWED_DEVIATION + duration) <= serverUnixTime) {
                        if (lastUnixTime + (UNIX_TIME_ALLOWED_DEVIATION + duration) >= serverUnixTime) {
                            matchCounter++;
                        }
                    }
                    lastUnixTime = serverUnixTime;
                }
            }
        }

        if (matchCounter >= MINIMUM_MATCH_COUNTER) {
            LOGGER.debug("ServerRandom utilizes UnixTimestamps.");
            return true;
        } else {
            LOGGER.debug("No UnixTimestamps detected.");
            return false;
        }
    }

    /**
     * Generates a new TLS 1.2 Connection for IV-Collection.
     *
     * @param config The TLS Config employed in the new Connection
     * @return State representing the newly opened TLS Connection
     */
    private State generateOpenConnection(Config config) {
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
        config.setWorkflowExecutorShouldClose(false);
        config.setAddServerNameIndicationExtension(true);
        config.setEarlyStop(true);
        config.setQuickReceive(true);
        config.setEnforceSettings(true);
        State state = new State(config);
        WorkflowExecutor workflowExecutor
                = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT, state);
        try {
            workflowExecutor.executeWorkflow();
        } catch (TransportHandlerConnectException ex) {
            LOGGER.debug("Could not open new Connection.", ex);
            return null;
        }
        tlsConnectionCounter++;
        return state;
    }
}
