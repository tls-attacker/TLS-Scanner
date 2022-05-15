/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.SetResult;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class CipherSuiteProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private List<ProtocolVersion> protocolVersions;

    private List<VersionSuiteListPair> pairLists;

    private TestResult supportsNullCiphers = TestResults.FALSE;
    private TestResult supportsAnonCiphers = TestResults.FALSE;
    private TestResult supportsExportCiphers = TestResults.FALSE;
    private TestResult supportsDesCiphers = TestResults.FALSE;
    private TestResult supportsSeedCiphers = TestResults.FALSE;
    private TestResult supportsIdeaCiphers = TestResults.FALSE;
    private TestResult supportsRc2Ciphers = TestResults.FALSE;
    private TestResult supportsRc4Ciphers = TestResults.FALSE;
    private TestResult supportsTripleDesCiphers = TestResults.FALSE;
    private TestResult supportsPostQuantumCiphers = TestResults.FALSE;
    private TestResult supportsAeadCiphers = TestResults.FALSE;
    private TestResult supportsPfsCiphers = TestResults.FALSE;
    private TestResult supportsOnlyPfsCiphers = TestResults.FALSE;
    private TestResult supportsAes = TestResults.FALSE;
    private TestResult supportsCamellia = TestResults.FALSE;
    private TestResult supportsAria = TestResults.FALSE;
    private TestResult supportsChacha = TestResults.FALSE;
    private TestResult supportsRsa = TestResults.FALSE;
    private TestResult supportsStaticEcdh = TestResults.FALSE;
    private TestResult supportsEcdsa = TestResults.FALSE;
    private TestResult supportsRsaCert = TestResults.FALSE;
    private TestResult supportsDss = TestResults.FALSE;
    private TestResult supportsGost = TestResults.FALSE;
    private TestResult supportsSrp = TestResults.FALSE;
    private TestResult supportsKerberos = TestResults.FALSE;
    private TestResult supportsPskPlain = TestResults.FALSE;
    private TestResult supportsPskRsa = TestResults.FALSE;
    private TestResult supportsPskDhe = TestResults.FALSE;
    private TestResult supportsPskEcdhe = TestResults.FALSE;
    private TestResult supportsFortezza = TestResults.FALSE;
    private TestResult supportsNewHope = TestResults.FALSE;
    private TestResult supportsEcmqv = TestResults.FALSE;
    private TestResult prefersPfsCiphers = TestResults.FALSE;
    private TestResult supportsStreamCiphers = TestResults.FALSE;
    private TestResult supportsBlockCiphers = TestResults.FALSE;
    private TestResult supportsLegacyPrf = TestResults.FALSE;
    private TestResult supportsSha256Prf = TestResults.FALSE;
    private TestResult supportsSha384Prf = TestResults.FALSE;

    public CipherSuiteProbe(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.CIPHER_SUITE, config);
        this.protocolVersions = new LinkedList<>();
        super.register(TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS, TlsAnalyzedProperty.SUPPORTS_ANON,
            TlsAnalyzedProperty.SUPPORTS_EXPORT, TlsAnalyzedProperty.SUPPORTS_DES, TlsAnalyzedProperty.SUPPORTS_SEED,
            TlsAnalyzedProperty.SUPPORTS_IDEA, TlsAnalyzedProperty.SUPPORTS_RC2, TlsAnalyzedProperty.SUPPORTS_RC4,
            TlsAnalyzedProperty.SUPPORTS_3DES, TlsAnalyzedProperty.SUPPORTS_POST_QUANTUM,
            TlsAnalyzedProperty.SUPPORTS_AEAD, TlsAnalyzedProperty.SUPPORTS_PFS, TlsAnalyzedProperty.SUPPORTS_ONLY_PFS,
            TlsAnalyzedProperty.SUPPORTS_AES, TlsAnalyzedProperty.SUPPORTS_CAMELLIA, TlsAnalyzedProperty.SUPPORTS_ARIA,
            TlsAnalyzedProperty.SUPPORTS_CHACHA, TlsAnalyzedProperty.SUPPORTS_RSA,
            TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH, TlsAnalyzedProperty.SUPPORTS_ECDSA,
            TlsAnalyzedProperty.SUPPORTS_RSA_CERT, TlsAnalyzedProperty.SUPPORTS_DSS, TlsAnalyzedProperty.SUPPORTS_GOST,
            TlsAnalyzedProperty.SUPPORTS_SRP, TlsAnalyzedProperty.SUPPORTS_KERBEROS,
            TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN, TlsAnalyzedProperty.SUPPORTS_PSK_RSA,
            TlsAnalyzedProperty.SUPPORTS_PSK_DHE, TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE,
            TlsAnalyzedProperty.SUPPORTS_FORTEZZA, TlsAnalyzedProperty.SUPPORTS_NEWHOPE,
            TlsAnalyzedProperty.SUPPORTS_ECMQV, TlsAnalyzedProperty.PREFERS_PFS,
            TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS, TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS,
            TlsAnalyzedProperty.SUPPORTS_LEGACY_PRF, TlsAnalyzedProperty.SUPPORTS_SHA256_PRF,
            TlsAnalyzedProperty.SUPPORTS_SHA384_PRF, TlsAnalyzedProperty.LIST_VERSIONSUITE_PAIRS,
            TlsAnalyzedProperty.SET_CIPHERSUITES);
    }

    @Override
    public void executeTest() {
        pairLists = new LinkedList<>();
        for (ProtocolVersion version : protocolVersions) {
            LOGGER.debug("Testing:" + version.name());
            if (version.isTLS13()) {
                pairLists.add(new VersionSuiteListPair(version, getSupportedCipherSuites()));
            } else {
                List<CipherSuite> toTestList = new LinkedList<>();
                List<CipherSuite> versionSupportedSuites = new LinkedList<>();
                if (version == ProtocolVersion.SSL3) {
                    toTestList.addAll(CipherSuite.SSL3_SUPPORTED_CIPHERSUITES);
                    versionSupportedSuites = getSupportedCipherSuitesWithIntolerance(toTestList, version);
                } else {
                    toTestList.addAll(Arrays.asList(CipherSuite.values()));
                    toTestList.remove(CipherSuite.TLS_FALLBACK_SCSV);
                    toTestList.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
                    versionSupportedSuites = getSupportedCipherSuitesWithIntolerance(toTestList, version);
                    if (versionSupportedSuites.isEmpty()) {
                        versionSupportedSuites = getSupportedCipherSuitesWithIntolerance(version);
                    }
                }
                if (versionSupportedSuites.size() > 0) {
                    pairLists.add(new VersionSuiteListPair(version, versionSupportedSuites));
                }
            }
        }
    }

    private List<CipherSuite> getSupportedCipherSuites() {
        CipherSuite selectedSuite = null;
        List<CipherSuite> toTestList = new LinkedList<>();
        List<CipherSuite> supportedSuits = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.values()) {
            if (suite.isTLS13()) {
                toTestList.add(suite);
            }
        }
        do {
            selectedSuite = getSelectedCipherSuite(toTestList);

            if (selectedSuite != null) {
                if (!toTestList.contains(selectedSuite)) {
                    LOGGER.warn("Server chose a CipherSuite we did not propose!");
                    // TODO write to site report
                    break;
                }
                supportedSuits.add(selectedSuite);
                toTestList.remove(selectedSuite);
            }
        } while (selectedSuite != null && !toTestList.isEmpty());
        return supportedSuits;
    }

    private CipherSuite getSelectedCipherSuite(List<CipherSuite> toTestList) {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(toTestList);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setDefaultClientKeyShareNamedGroups(new LinkedList<>());
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setAddCertificateStatusRequestExtension(true);
        tlsConfig.setUseFreshRandom(true);
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(
            SignatureAndHashAlgorithm.getImplementedTls13SignatureAndHashAlgorithms());

        State state = new State(tlsConfig);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
            return state.getTlsContext().getSelectedCipherSuite();
        } else if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.HELLO_RETRY_REQUEST,
            state.getWorkflowTrace())) {
            return state.getTlsContext().getSelectedCipherSuite();
        } else {
            LOGGER.debug("Did not receive ServerHello Message");
            LOGGER.debug(state.getWorkflowTrace().toString());
            return null;
        }
    }

    public List<CipherSuite> getSupportedCipherSuitesWithIntolerance(ProtocolVersion version) {
        return getSupportedCipherSuitesWithIntolerance(new ArrayList<>(CipherSuite.getImplemented()), version);
    }

    public List<CipherSuite> getSupportedCipherSuitesWithIntolerance(List<CipherSuite> toTestList,
        ProtocolVersion version) {
        List<CipherSuite> listWeSupport = new LinkedList<>(toTestList);
        List<CipherSuite> supported = new LinkedList<>();

        boolean supportsMore = false;
        do {
            Config config = getScannerConfig().createConfig();
            config.setDefaultClientSupportedCipherSuites(listWeSupport);
            config.setDefaultSelectedProtocolVersion(version);
            config.setHighestProtocolVersion(version);
            config.setEnforceSettings(true);
            boolean containsEc = false;
            for (CipherSuite suite : config.getDefaultClientSupportedCipherSuites()) {
                KeyExchangeAlgorithm keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(suite);
                if (keyExchangeAlgorithm != null && keyExchangeAlgorithm.name().toUpperCase().contains("EC")) {
                    containsEc = true;
                    break;
                }
            }
            config.setAddEllipticCurveExtension(containsEc);
            config.setAddECPointFormatExtension(containsEc);
            config.setAddSignatureAndHashAlgorithmsExtension(true);
            config.setAddRenegotiationInfoExtension(true);
            config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
            config.setQuickReceive(true);
            config.setEarlyStop(true);
            config.setStopReceivingAfterFatal(true);
            config.setStopActionsAfterIOException(true);
            config.setStopActionsAfterFatal(true);
            List<NamedGroup> namedGroup = new LinkedList<>();
            namedGroup.addAll(Arrays.asList(NamedGroup.values()));
            config.setDefaultClientNamedGroups(namedGroup);
            State state = new State(config);
            executeState(state);
            if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace())) {
                if (state.getTlsContext().getSelectedProtocolVersion() != version) {
                    LOGGER.debug("Server does not support " + version);
                    return new LinkedList<>();
                }
                LOGGER.debug("Server chose " + state.getTlsContext().getSelectedCipherSuite().name());
                if (listWeSupport.contains(state.getTlsContext().getSelectedCipherSuite())) {
                    supportsMore = true;
                    supported.add(state.getTlsContext().getSelectedCipherSuite());
                    listWeSupport.remove(state.getTlsContext().getSelectedCipherSuite());
                } else {
                    supportsMore = false;
                    LOGGER.warn("Server chose not proposed cipher suite");
                }
            } else {
                supportsMore = false;
                LOGGER.debug("Server did not send ServerHello");
                LOGGER.debug(state.getWorkflowTrace().toString());
                if (state.getTlsContext().isReceivedFatalAlert()) {
                    LOGGER.debug("Received Fatal Alert");
                    AlertMessage alert = (AlertMessage) WorkflowTraceUtil
                        .getFirstReceivedMessage(ProtocolMessageType.ALERT, state.getWorkflowTrace());
                    LOGGER.debug("Type:" + alert.toString());

                }
            }
        } while (supportsMore);
        return supported;
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        return new ProbeRequirement(report).requireProbeTypes(TlsProbeType.PROTOCOL_VERSION);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.DTLS10);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.DTLS12);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_SSL_3) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.SSL3);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.TLS10);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.TLS11);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.TLS12);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.TLS13);
        }
    }

    @Override
    public CipherSuiteProbe getCouldNotExecuteResult() {
        pairLists = null;
        return this;
    }

    @Override
    protected void mergeData(ServerReport report) {
        if (pairLists != null) {
            Set<CipherSuite> allSupported = new HashSet<>();
            supportsOnlyPfsCiphers = TestResults.TRUE;
            prefersPfsCiphers = TestResults.TRUE;
            for (VersionSuiteListPair pair : pairLists) {
                if (pair.getCipherSuiteList().size() > 0 && !pair.getCipherSuiteList().get(0).isEphemeral())
                    prefersPfsCiphers = TestResults.FALSE;
                allSupported.addAll(pair.getCipherSuiteList());

                for (CipherSuite suite : pair.getCipherSuiteList()) {
                    PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(pair.getVersion(), suite);
                    if (prfAlgorithm == PRFAlgorithm.TLS_PRF_LEGACY)
                        supportsLegacyPrf = TestResults.TRUE;
                    if (prfAlgorithm == PRFAlgorithm.TLS_PRF_LEGACY)
                        supportsSha256Prf = TestResults.TRUE;
                    if (prfAlgorithm == PRFAlgorithm.TLS_PRF_LEGACY)
                        supportsSha384Prf = TestResults.TRUE;
                }
            }
            for (CipherSuite suite : allSupported) {
                adjustBulk(suite);
                adjustKeyExchange(suite);
                adjustCipherType(suite);
                adjustCertificate(suite);
            }
            super.put(TlsAnalyzedProperty.SET_CIPHERSUITES, new SetResult<CipherSuite>(allSupported, "CIPHERSUITES"));
        } else {
            supportsAeadCiphers = TestResults.COULD_NOT_TEST;
            prefersPfsCiphers = TestResults.COULD_NOT_TEST;
            supportsAeadCiphers = TestResults.COULD_NOT_TEST;
            supportsAes = TestResults.COULD_NOT_TEST;
            supportsAnonCiphers = TestResults.COULD_NOT_TEST;
            supportsAria = TestResults.COULD_NOT_TEST;
            supportsBlockCiphers = TestResults.COULD_NOT_TEST;
            supportsCamellia = TestResults.COULD_NOT_TEST;
            supportsChacha = TestResults.COULD_NOT_TEST;
            supportsDesCiphers = TestResults.COULD_NOT_TEST;
            supportsEcmqv = TestResults.COULD_NOT_TEST;
            supportsExportCiphers = TestResults.COULD_NOT_TEST;
            supportsFortezza = TestResults.COULD_NOT_TEST;
            supportsGost = TestResults.COULD_NOT_TEST;
            supportsIdeaCiphers = TestResults.COULD_NOT_TEST;
            supportsKerberos = TestResults.COULD_NOT_TEST;
            supportsNewHope = TestResults.COULD_NOT_TEST;
            supportsNullCiphers = TestResults.COULD_NOT_TEST;
            supportsOnlyPfsCiphers = TestResults.COULD_NOT_TEST;
            supportsPfsCiphers = TestResults.COULD_NOT_TEST;
            supportsPostQuantumCiphers = TestResults.COULD_NOT_TEST;
            supportsPskDhe = TestResults.COULD_NOT_TEST;
            supportsPskEcdhe = TestResults.COULD_NOT_TEST;
            supportsPskPlain = TestResults.COULD_NOT_TEST;
            supportsPskRsa = TestResults.COULD_NOT_TEST;
            supportsRc2Ciphers = TestResults.COULD_NOT_TEST;
            supportsRc4Ciphers = TestResults.COULD_NOT_TEST;
            supportsRsa = TestResults.COULD_NOT_TEST;
            supportsSeedCiphers = TestResults.COULD_NOT_TEST;
            supportsSrp = TestResults.COULD_NOT_TEST;
            supportsStaticEcdh = TestResults.COULD_NOT_TEST;
            supportsEcdsa = TestResults.COULD_NOT_TEST;
            supportsRsaCert = TestResults.COULD_NOT_TEST;
            supportsDss = TestResults.COULD_NOT_TEST;
            supportsStreamCiphers = TestResults.COULD_NOT_TEST;
            supportsTripleDesCiphers = TestResults.COULD_NOT_TEST;
            supportsLegacyPrf = TestResults.COULD_NOT_TEST;
            supportsSha256Prf = TestResults.COULD_NOT_TEST;
            supportsSha384Prf = TestResults.COULD_NOT_TEST;
            super.put(TlsAnalyzedProperty.SET_CIPHERSUITES, new SetResult<>(Collections.emptySet(), "CIPHERSUITES"));
        }
        writeToReport(report);
    }

    private void adjustCipherType(CipherSuite suite) {
        CipherType cipherType = AlgorithmResolver.getCipherType(suite);
        switch (cipherType) {
            case AEAD:
                supportsAeadCiphers = TestResults.TRUE;
                break;
            case BLOCK:
                supportsBlockCiphers = TestResults.TRUE;
                break;
            case STREAM:
                supportsStreamCiphers = TestResults.TRUE;
                break;
            default:
                ;
        }
    }

    private void adjustKeyExchange(CipherSuite suite) {
        if (suite.name().contains("SRP"))
            supportsSrp = TestResults.TRUE;
        if (suite.name().contains("TLS_RSA"))
            supportsRsa = TestResults.TRUE;
        if (suite.name().contains("ECDH_"))
            supportsStaticEcdh = TestResults.TRUE;
        if (suite.name().contains("NULL"))
            supportsNullCiphers = TestResults.TRUE;
        if (suite.name().contains("GOST"))
            supportsGost = TestResults.TRUE;
        if (suite.name().contains("KRB5"))
            supportsKerberos = TestResults.TRUE;
        if (suite.name().contains("TLS_PSK_WITH"))
            supportsPskPlain = TestResults.TRUE;
        if (suite.name().contains("_DHE_PSK"))
            supportsPskDhe = TestResults.TRUE;
        if (suite.name().contains("ECDHE_PSK"))
            supportsPskEcdhe = TestResults.TRUE;
        if (suite.name().contains("RSA_PSK"))
            supportsPskRsa = TestResults.TRUE;
        if (suite.name().contains("FORTEZZA"))
            supportsFortezza = TestResults.TRUE;
        if (suite.name().contains("ECMQV")) {
            supportsPostQuantumCiphers = TestResults.TRUE;
            supportsEcmqv = TestResults.TRUE;
        }
        if (suite.name().contains("CECPQ1")) {
            supportsPostQuantumCiphers = TestResults.TRUE;
            supportsNewHope = TestResults.TRUE;
        }
        if (suite.name().contains("anon"))
            supportsAnonCiphers = TestResults.TRUE;
        if (suite.isEphemeral())
            supportsPfsCiphers = TestResults.TRUE;
        else
            supportsOnlyPfsCiphers = TestResults.FALSE;
        if (suite.isExport())
            supportsExportCiphers = TestResults.TRUE;
    }

    private void adjustBulk(CipherSuite suite) {
        BulkCipherAlgorithm bulkCipherAlgorithm = AlgorithmResolver.getBulkCipherAlgorithm(suite);
        switch (bulkCipherAlgorithm) {
            case AES:
                supportsAes = TestResults.TRUE;
                break;
            case CAMELLIA:
                supportsCamellia = TestResults.TRUE;
                break;
            case DES40:
                supportsDesCiphers = TestResults.TRUE;
                supportsExportCiphers = TestResults.TRUE;
                break;
            case DES:
                supportsDesCiphers = TestResults.TRUE;
                break;
            case ARIA:
                supportsAria = TestResults.TRUE;
                break;
            case DESede:
                supportsTripleDesCiphers = TestResults.TRUE;
                break;
            case FORTEZZA:
                supportsFortezza = TestResults.TRUE;
                break;
            case IDEA:
                supportsIdeaCiphers = TestResults.TRUE;
                break;
            case NULL:
                supportsNullCiphers = TestResults.TRUE;
                break;
            case RC2:
                supportsRc2Ciphers = TestResults.TRUE;
                break;
            case RC4:
                supportsRc4Ciphers = TestResults.TRUE;
                break;
            case SEED:
                supportsSeedCiphers = TestResults.TRUE;
                break;
            case CHACHA20_POLY1305:
                supportsChacha = TestResults.TRUE;
                break;
            default:
                ;
        }
    }

    private void adjustCertificate(CipherSuite suite) {
        if (suite.name().contains("ECDSA"))
            supportsEcdsa = TestResults.TRUE;
        if (suite.name().contains("DSS"))
            supportsDss = TestResults.TRUE;
        if (suite.name().contains("RSA"))
            supportsRsaCert = TestResults.TRUE;
    }

    private void writeToReport(ServerReport report) {
        super.put(TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS, supportsNullCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_ANON, supportsAnonCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_EXPORT, supportsExportCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_DES, supportsDesCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_SEED, supportsSeedCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_IDEA, supportsIdeaCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_RC2, supportsRc2Ciphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_RC4, supportsRc4Ciphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_3DES, supportsTripleDesCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_POST_QUANTUM, supportsPostQuantumCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_AEAD, supportsAeadCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_PFS, supportsPfsCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_ONLY_PFS, supportsOnlyPfsCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_AES, supportsAes);
        super.put(TlsAnalyzedProperty.SUPPORTS_CAMELLIA, supportsCamellia);
        super.put(TlsAnalyzedProperty.SUPPORTS_ARIA, supportsAria);
        super.put(TlsAnalyzedProperty.SUPPORTS_CHACHA, supportsChacha);
        super.put(TlsAnalyzedProperty.SUPPORTS_RSA, supportsRsa);
        super.put(TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH, supportsStaticEcdh);
        super.put(TlsAnalyzedProperty.SUPPORTS_ECDSA, supportsEcdsa);
        super.put(TlsAnalyzedProperty.SUPPORTS_RSA_CERT, supportsRsaCert);
        super.put(TlsAnalyzedProperty.SUPPORTS_DSS, supportsDss);
        super.put(TlsAnalyzedProperty.SUPPORTS_GOST, supportsGost);
        super.put(TlsAnalyzedProperty.SUPPORTS_SRP, supportsSrp);
        super.put(TlsAnalyzedProperty.SUPPORTS_KERBEROS, supportsKerberos);
        super.put(TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN, supportsPskPlain);
        super.put(TlsAnalyzedProperty.SUPPORTS_PSK_RSA, supportsPskRsa);
        super.put(TlsAnalyzedProperty.SUPPORTS_PSK_DHE, supportsPskDhe);
        super.put(TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE, supportsPskEcdhe);
        super.put(TlsAnalyzedProperty.SUPPORTS_FORTEZZA, supportsFortezza);
        super.put(TlsAnalyzedProperty.SUPPORTS_NEWHOPE, supportsNewHope);
        super.put(TlsAnalyzedProperty.SUPPORTS_ECMQV, supportsEcmqv);
        super.put(TlsAnalyzedProperty.PREFERS_PFS, prefersPfsCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS, supportsStreamCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS, supportsBlockCiphers);
        super.put(TlsAnalyzedProperty.SUPPORTS_LEGACY_PRF, supportsLegacyPrf);
        super.put(TlsAnalyzedProperty.SUPPORTS_SHA256_PRF, supportsSha256Prf);
        super.put(TlsAnalyzedProperty.SUPPORTS_SHA384_PRF, supportsSha384Prf);
        super.put(TlsAnalyzedProperty.LIST_VERSIONSUITE_PAIRS, new ListResult<>(pairLists, "VERSIONSUITE_PAIRS"));
    }
}
