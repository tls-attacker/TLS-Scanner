/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackConfig;
import de.rub.nds.tlsattacker.attacks.ec.InvalidCurvePoint;
import de.rub.nds.tlsattacker.attacks.ec.TwistedCurvePoint;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttacker;
import de.rub.nds.tlsattacker.attacks.util.response.FingerprintSecretPair;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurveOverFp;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.probe.namedcurve.NamedCurveWitness;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidCurve.InvalidCurveVector;
import de.rub.nds.tlsscanner.serverscanner.probe.invalidCurve.InvalidCurveResponse;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.InvalidCurveResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class InvalidCurveProbe extends TlsProbe {

    /**
     * Defines the error probability for each test vector
     */
    private final double ERROR_PROBABILITY = 0.001; // increase if needed

    private boolean supportsRenegotiation;

    private TestResult supportsSecureRenegotiation;

    private TestResult issuesTls13SessionTickets;

    private TestResult supportsTls13PskDhe;

    private List<ProtocolVersion> supportedProtocolVersions;

    private List<NamedGroup> supportedFpGroups;

    private List<NamedGroup> supportedTls13FpGroups;

    private HashMap<ProtocolVersion, List<CipherSuite>> supportedECDHCipherSuites;

    private List<ECPointFormat> fpPointFormatsToTest;

    private List<ECPointFormat> tls13FpPointFormatsToTest;

    private Map<NamedGroup, NamedCurveWitness> namedCurveWitnesses;

    private Map<NamedGroup, NamedCurveWitness> namedCurveWitnessesTls13;

    private int parameterCombinations;
    private int executedCombinations = 0;
    
    private final int additionalOverall = 100;

    public InvalidCurveProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.INVALID_CURVE, config);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<InvalidCurveVector> parameterSets = prepareParameterCombinations();
            List<InvalidCurveResponse> responses = new LinkedList<>();
            for (InvalidCurveVector parameterSet : parameterSets) {
                if (benignHandshakeSuccessfull(parameterSet)) {
                    InvalidCurveResponse scanResponse = executeSingleScan(parameterSet, false);
                    if(fingerprintsDiffer(scanResponse)) {
                        InvalidCurveResponse repetitionResponse = executeSingleScan(parameterSet, true);
                        scanResponse.mergeResponse(repetitionResponse);
                    }
                    responses.add(scanResponse);
                }
            }
            return evaluateResponses(responses);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new InvalidCurveResult(TestResult.ERROR_DURING_TEST, TestResult.ERROR_DURING_TEST,
                    TestResult.ERROR_DURING_TEST, null);
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (report.getResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION) == TestResult.NOT_TESTED_YET
                || !report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION)
                || !report.isProbeAlreadyExecuted(ProbeType.CIPHERSUITE)
                || !report.isProbeAlreadyExecuted(ProbeType.NAMED_GROUPS)
                || !report.isProbeAlreadyExecuted(ProbeType.RESUMPTION)) {
            return false; // dependency is missing
        } else if (report.getResult(AnalyzedProperty.SUPPORTS_ECDH) != TestResult.TRUE
                && report.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) != TestResult.TRUE
                && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) != TestResult.TRUE) {
            return false; // can actually not be exectued
        } else {
            return true;
        }
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportsRenegotiation = (report.getResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION) == TestResult.TRUE || report
                .getResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION) == TestResult.TRUE);
        supportsSecureRenegotiation = report.getResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION);
        issuesTls13SessionTickets = report.getResult(AnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS);
        supportsTls13PskDhe = report.getResult(AnalyzedProperty.SUPPORTS_TLS13_PSK_DHE);

        supportedFpGroups = new LinkedList<>();
        if (report.getSupportedNamedGroups() != null) {
            for (NamedGroup group : report.getSupportedNamedGroups()) {
                if (NamedGroup.getImplemented().contains(group)
                        && CurveFactory.getCurve(group) instanceof EllipticCurveOverFp) {
                    supportedFpGroups.add(group);
                }
            }
        } else {
            LOGGER.warn("Supported Named Groups list has not been initialized");
        }

        HashMap<ProtocolVersion, List<CipherSuite>> cipherSuitesMap = new HashMap<>();
        if (report.getVersionSuitePairs() != null) {
            for (VersionSuiteListPair pair : report.getVersionSuitePairs()) {
                if (!cipherSuitesMap.containsKey(pair.getVersion())) {
                    cipherSuitesMap.put(pair.getVersion(), new LinkedList<>());
                }
                for (CipherSuite cipherSuite : pair.getCiphersuiteList()) {
                    if (cipherSuite.name().contains("TLS_ECDH")) {
                        cipherSuitesMap.get(pair.getVersion()).add(cipherSuite);
                    }
                }

            }
        } else {
            LOGGER.warn("Supported CipherSuites list has not been initialized");
        }

        List<ECPointFormat> fpPointFormats = new LinkedList<>();
        fpPointFormats.add(ECPointFormat.UNCOMPRESSED);
        if (report.getResult(AnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT) != TestResult.TRUE) {
            LOGGER.warn("Server did not list uncompressed points as supported");
        }
        if (report.getResult(AnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME) == TestResult.TRUE
                || getScannerConfig().getScanDetail() == ScannerDetail.ALL) {
            fpPointFormats.add(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        }

        List<ProtocolVersion> protocolVersions = new LinkedList<>();
        if (report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.TRUE) {
            protocolVersions.add(ProtocolVersion.TLS10);
        }
        if (report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.TRUE) {
            protocolVersions.add(ProtocolVersion.TLS11);
        }
        if (report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.TRUE) {
            protocolVersions.add(ProtocolVersion.TLS12);
        }
        supportedTls13FpGroups = new LinkedList();
        if (report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.TRUE) {
            protocolVersions.add(ProtocolVersion.TLS13);
            for (NamedGroup group : report.getSupportedTls13Groups()) {
                if (NamedGroup.getImplemented().contains(group)
                        && CurveFactory.getCurve(group) instanceof EllipticCurveOverFp) {
                    supportedTls13FpGroups.add(group);
                }
            }

            List<CipherSuite> tls13CipherSuites = new LinkedList<>();
            for (VersionSuiteListPair pair : report.getVersionSuitePairs()) {
                if (pair.getVersion().isTLS13()) {
                    for (CipherSuite cipherSuite : pair.getCiphersuiteList()) {
                        if (cipherSuite.isImplemented()) {
                            tls13CipherSuites.add(cipherSuite);
                        }
                    }
                }
            }

            List<ECPointFormat> tls13FpPointFormats = new LinkedList<>();
            tls13FpPointFormats.add(ECPointFormat.UNCOMPRESSED);
            if (report.getResult(AnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION) == TestResult.TRUE) {
                tls13FpPointFormats.add(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
            }

            cipherSuitesMap.put(ProtocolVersion.TLS13, tls13CipherSuites);
            tls13FpPointFormatsToTest = tls13FpPointFormats;
        }

        // sometimes we found more versions while testing ciphersuites
        if (cipherSuitesMap.keySet().size() > protocolVersions.size()) {
            for (ProtocolVersion version : cipherSuitesMap.keySet()) {
                if (!protocolVersions.contains(version)) {
                    protocolVersions.add(version);
                }
            }
        }

        fpPointFormatsToTest = fpPointFormats;
        supportedProtocolVersions = protocolVersions;
        supportedECDHCipherSuites = cipherSuitesMap;
        namedCurveWitnesses = report.getSupportedNamedGroupsWitnesses();
        namedCurveWitnessesTls13 = report.getSupportedNamedGroupsWitnessesTls13();

    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new InvalidCurveResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
                null);
    }

    private InvalidCurveAttacker prepareAttacker(InvalidCurveAttackConfig attackConfig,
            ProtocolVersion protocolVersion, List<CipherSuite> cipherSuites, NamedGroup group,
            List<NamedGroup> ecdsaRequiredGroups) {
        ClientDelegate delegate = (ClientDelegate) attackConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        StarttlsDelegate starttlsDelegate = (StarttlsDelegate) attackConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
        InvalidCurveAttacker attacker = new InvalidCurveAttacker(attackConfig, attackConfig.createConfig(),
                getParallelExecutor());

        if (protocolVersion == ProtocolVersion.TLS13) {
            attacker.getTlsConfig().setAddKeyShareExtension(true);
            List<NamedGroup> keyShareGroups = new LinkedList<>();
            keyShareGroups.add(group);
            attacker.getTlsConfig().setDefaultClientKeyShareNamedGroups(keyShareGroups);
            attacker.getTlsConfig().setAddECPointFormatExtension(false);
            attacker.getTlsConfig().setAddSupportedVersionsExtension(true);
            attacker.getTlsConfig().setAddPSKKeyExchangeModesExtension(true);
            List<PskKeyExchangeMode> pskKex = new LinkedList<>();
            pskKex.add(PskKeyExchangeMode.PSK_DHE_KE);
            attacker.getTlsConfig().setPSKKeyExchangeModes(pskKex);
            attacker.getTlsConfig().setDefaultClientSupportedSignatureAndHashAlgorithms(
                    getTls13SignatureAndHashAlgorithms());
        }

        attacker.getTlsConfig().setHighestProtocolVersion(protocolVersion);
        attacker.getTlsConfig().setDefaultSelectedProtocolVersion(protocolVersion);
        attacker.getTlsConfig().setDefaultClientSupportedCiphersuites(cipherSuites);
        attacker.getTlsConfig().setDefaultClientNamedGroups(group);
        attacker.getTlsConfig().setDefaultSelectedNamedGroup(group);

        // avoid cases where the server requires an additional group
        // to sign a PK of our testgroup using ECDSA
        if (!ecdsaRequiredGroups.isEmpty()) {
            attacker.getTlsConfig().getDefaultClientNamedGroups().addAll(ecdsaRequiredGroups);
        }

        if (supportsSecureRenegotiation == TestResult.TRUE) {
            attacker.getTlsConfig().setAddRenegotiationInfoExtension(true);
        } else {
            attacker.getTlsConfig().setAddRenegotiationInfoExtension(false);
        }
        return attacker;
    }

    private List<InvalidCurveVector> prepareParameterCombinations() {
        LinkedList<InvalidCurveVector> parameterSets = new LinkedList<>();

        List<ProtocolVersion> pickedProtocolVersions = pickProtocolVersions();
        for (ProtocolVersion protocolVersion : supportedProtocolVersions) {
            List<NamedGroup> groupList;
            List<ECPointFormat> formatList;
            if (protocolVersion == ProtocolVersion.TLS13) {
                groupList = supportedTls13FpGroups;
                formatList = tls13FpPointFormatsToTest;
            } else {
                groupList = supportedFpGroups;
                formatList = fpPointFormatsToTest;
            }
            for (NamedGroup group : groupList) {

                for (ECPointFormat format : formatList) {
                    if (supportedECDHCipherSuites.get(protocolVersion) == null) {
                        LOGGER.warn("Protocol Version " + protocolVersion
                                + " had no entry in Ciphersuite map - omitting from InvalidCurve scan");
                    } else {
                        if (scannerConfig.getScanDetail() == ScannerDetail.ALL) {
                            // individual scans for every ciphersuite
                            for (CipherSuite cipherSuite : supportedECDHCipherSuites.get(protocolVersion)) {
                                if (legitInvalidCurveVector(group, format)
                                        && groupQualifiedForCiphersuite(group, cipherSuite)) {
                                    parameterSets.add(new InvalidCurveVector(protocolVersion, cipherSuite, group,
                                            format, false, false, getRequiredGroups(group, cipherSuite)));
                                }
                                if (legitTwistVector(group, format) && groupQualifiedForCiphersuite(group, cipherSuite)) {
                                    parameterSets.add(new InvalidCurveVector(protocolVersion, cipherSuite, group,
                                            format, true, false, getRequiredGroups(group, cipherSuite)));
                                }
                            }
                        } else {
                            // reduced list of ciphersuites (varying by
                            // ScannerDetail)
                            HashMap<ProtocolVersion, List<CipherSuite>> filteredCipherSuites = filterCipherSuites(group);
                            if (pickedProtocolVersions.contains(protocolVersion)
                                    || scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
                                List<CipherSuite> versionSuiteList = filteredCipherSuites.get(protocolVersion);
                                for (CipherSuite cipherSuite : versionSuiteList) {
                                    if (legitInvalidCurveVector(group, format)) {
                                        parameterSets.add(new InvalidCurveVector(protocolVersion, cipherSuite, group,
                                                format, false, false, getRequiredGroups(group, cipherSuite)));
                                    }
                                    if (legitTwistVector(group, format)) {
                                        parameterSets.add(new InvalidCurveVector(protocolVersion, cipherSuite, group,
                                                format, true, false, getRequiredGroups(group, cipherSuite)));
                                    }
                                }
                            }
                        }
                    }
                }

            }
        }

        // repeat scans in renegotiation
        if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
            ProtocolVersion renegVersion = pickRenegotiationVersion();
            int setCount = parameterSets.size();
            if (scannerConfig.getScanDetail() == ScannerDetail.ALL) {
                // scan all possible combinations in renegotiation
                for (int i = 0; i < setCount; i++) {
                    InvalidCurveVector set = parameterSets.get(i);
                    if ((set.getProtocolVersion() == ProtocolVersion.TLS13 && (issuesTls13SessionTickets == TestResult.TRUE && supportsTls13PskDhe == TestResult.TRUE))
                            || supportsRenegotiation) {
                        parameterSets.add(new InvalidCurveVector(set.getProtocolVersion(), set.getCipherSuite(), set
                                .getNamedGroup(), set.getPointFormat(), set.isTwistAttack(), true, set
                                .getEcdsaRequiredGroups()));
                    }
                }
            } else if (renegVersion != null) {
                // scan only one version in renegotiation
                for (int i = 0; i < setCount; i++) {
                    InvalidCurveVector set = parameterSets.get(i);
                    if (set.getProtocolVersion() == renegVersion) {
                        parameterSets.add(new InvalidCurveVector(set.getProtocolVersion(), set.getCipherSuite(), set
                                .getNamedGroup(), set.getPointFormat(), set.isTwistAttack(), true, set
                                .getEcdsaRequiredGroups()));
                    }
                }
            }

        }
        return parameterSets;
    }

    private InvalidCurveResponse executeSingleScan(InvalidCurveVector parameterSet, boolean isRepetitionScan) {
        LOGGER.debug("Executing Invalid Curve scan for " + parameterSet.toString());
        try {
            TestResult showsPointsAreNotValidated = TestResult.NOT_TESTED_YET;

            InvalidCurveAttackConfig invalidCurveAttackConfig = new InvalidCurveAttackConfig(getScannerConfig()
                    .getGeneralDelegate());
            invalidCurveAttackConfig.setNamedGroup(parameterSet.getNamedGroup());
            invalidCurveAttackConfig.setAttackInRenegotiation(parameterSet.isAttackInRenegotiation());

            if (parameterSet.isTwistAttack()) {

                invalidCurveAttackConfig.setPublicPointBaseX(TwistedCurvePoint.fromIntendedNamedGroup(
                        parameterSet.getNamedGroup()).getPublicPointBaseX());
                invalidCurveAttackConfig.setPublicPointBaseY(TwistedCurvePoint.fromIntendedNamedGroup(
                        parameterSet.getNamedGroup()).getPublicPointBaseY());
                if (parameterSet.getNamedGroup() == NamedGroup.ECDH_X25519
                        || parameterSet.getNamedGroup() == NamedGroup.ECDH_X448) {
                    invalidCurveAttackConfig.setProtocolFlows(1);
                } else {
                    double errorAttempt = (double) (TwistedCurvePoint
                            .fromIntendedNamedGroup(parameterSet.getNamedGroup()).getOrder().intValue() - 2)
                            / TwistedCurvePoint.fromIntendedNamedGroup(parameterSet.getNamedGroup()).getOrder()
                                    .intValue();
                    double attempts = Math.log(ERROR_PROBABILITY) / Math.log(errorAttempt);
                    int additionalIterations = (additionalOverall - (int) Math.ceil(attempts));
                    
                    if(isRepetitionScan && additionalIterations > 0) 
                    {
                        invalidCurveAttackConfig.setKeyOffset((int) Math.ceil(attempts));
                        invalidCurveAttackConfig.setProtocolFlows(additionalIterations);
                    }
                    else
                    {
                       invalidCurveAttackConfig.setProtocolFlows((int) Math.ceil(attempts)); 
                    }
                    
                }
                invalidCurveAttackConfig.setPointCompressionFormat(parameterSet.getPointFormat());

                invalidCurveAttackConfig.setCurveTwistAttack(true);
                invalidCurveAttackConfig.setCurveTwistD(TwistedCurvePoint.fromIntendedNamedGroup(
                        parameterSet.getNamedGroup()).getD());
            } else {
                invalidCurveAttackConfig.setPublicPointBaseX(InvalidCurvePoint.fromNamedGroup(
                        parameterSet.getNamedGroup()).getPublicPointBaseX());
                invalidCurveAttackConfig.setPublicPointBaseY(InvalidCurvePoint.fromNamedGroup(
                        parameterSet.getNamedGroup()).getPublicPointBaseY());

                double errorAttempt = (double) (InvalidCurvePoint.fromNamedGroup(parameterSet.getNamedGroup())
                        .getOrder().intValue() - 2)
                        / InvalidCurvePoint.fromNamedGroup(parameterSet.getNamedGroup()).getOrder().intValue();
                double attempts = Math.log(ERROR_PROBABILITY) / Math.log(errorAttempt);
                int additionalIterations = (additionalOverall - (int) Math.ceil(attempts));
                
                if(isRepetitionScan && additionalIterations > 0) 
                {
                    invalidCurveAttackConfig.setKeyOffset((int) Math.ceil(attempts));
                    invalidCurveAttackConfig.setProtocolFlows(additionalIterations);
                }
                else
                {
                    invalidCurveAttackConfig.setProtocolFlows((int) Math.ceil(attempts)); 
                }
                invalidCurveAttackConfig.setPointCompressionFormat(ECPointFormat.UNCOMPRESSED);
            }

            InvalidCurveAttacker attacker = prepareAttacker(invalidCurveAttackConfig,
                    parameterSet.getProtocolVersion(), parameterSet.getCipherSuiteAsList(),
                    parameterSet.getNamedGroup(), parameterSet.getEcdsaRequiredGroups());
            Boolean foundCongruence = attacker.isVulnerable();

            if (foundCongruence == null) {
                LOGGER.warn("Was unable to determine if points are validated for " + parameterSet.toString());
                showsPointsAreNotValidated = TestResult.ERROR_DURING_TEST;
            } else if (foundCongruence == true) {
                showsPointsAreNotValidated = TestResult.TRUE;
            } else {
                showsPointsAreNotValidated = TestResult.FALSE;
            }
            TestResult dirtyKeysWarning;
            if (attacker.isDirtyKeysWarning()) {
                dirtyKeysWarning = TestResult.TRUE;
            } else {
                dirtyKeysWarning = TestResult.FALSE;
            }
            return new InvalidCurveResponse(parameterSet, attacker.getResponsePairs(), showsPointsAreNotValidated,
                    attacker.getReceivedEcPublicKeys(), attacker.getFinishedKeys(), dirtyKeysWarning);
        } catch (Exception ex) {
            LOGGER.warn("Was unable to get results for " + parameterSet.toString() + " Message: " + ex.getMessage());
            return new InvalidCurveResponse(parameterSet, TestResult.ERROR_DURING_TEST);
        }
    }

    private InvalidCurveResult evaluateResponses(List<InvalidCurveResponse> responses) {
        TestResult vulnerableClassic = TestResult.FALSE;
        TestResult vulnerableEphemeral = TestResult.FALSE;
        TestResult vulnerableTwist = TestResult.FALSE;

        evaluateKeyBehavior(responses);

        for (InvalidCurveResponse response : responses) {
            if (response.getShowsPointsAreNotValidated() == TestResult.TRUE
                    && response.getChosenGroupReusesKey() == TestResult.TRUE) {
                if (response.getParameterSet().isTwistAttack()
                        && TwistedCurvePoint.isTwistVulnerable(response.getParameterSet().getNamedGroup())) {
                    response.setShowsVulnerability(TestResult.TRUE);
                    vulnerableTwist = TestResult.TRUE;
                } else if (!response.getParameterSet().isTwistAttack()) {
                    response.setShowsVulnerability(TestResult.TRUE);
                    if (response.getParameterSet().getCipherSuite().isEphemeral()) {
                        vulnerableEphemeral = TestResult.TRUE;
                    } else {
                        vulnerableClassic = TestResult.TRUE;
                    }
                }
            } else {
                response.setShowsVulnerability(TestResult.FALSE);
            }
        }

        return new InvalidCurveResult(vulnerableClassic, vulnerableEphemeral, vulnerableTwist, responses);
    }

    private void evaluateKeyBehavior(List<InvalidCurveResponse> responses) {
        for (InvalidCurveResponse response : responses) {
            if (response.getReceivedEcPublicKeys() == null || response.getReceivedEcPublicKeys().isEmpty()) {
                response.setChosenGroupReusesKey(TestResult.ERROR_DURING_TEST);
            } else {
                TestResult foundDuplicate = TestResult.FALSE;
                TestResult foundDuplicateFinished = TestResult.FALSE;
                for (Point point : response.getReceivedEcPublicKeys()) {
                    for (Point cPoint : response.getReceivedEcPublicKeys()) {
                        if (point != cPoint && (point.getX().getData().compareTo(cPoint.getX().getData()) == 0)
                                && point.getY().getData().compareTo(cPoint.getY().getData()) == 0) {
                            foundDuplicate = TestResult.TRUE;
                        }
                    }
                }

                // Compare again for keys from handshakes that lead to a
                // Finished message
                for (Point point : response.getReceivedFinishedEcKeys()) {
                    for (Point cPoint : response.getReceivedEcPublicKeys()) {
                        if (point != cPoint && (point.getX().getData().compareTo(cPoint.getX().getData()) == 0)
                                && point.getY().getData().compareTo(cPoint.getY().getData()) == 0) {
                            foundDuplicateFinished = TestResult.TRUE;
                        }
                    }
                }
                response.setChosenGroupReusesKey(foundDuplicate);
                response.setFinishedHandshakeHadReusedKey(foundDuplicateFinished);
            }
        }
    }

    private boolean legitInvalidCurveVector(NamedGroup group, ECPointFormat format) {
        if (format != ECPointFormat.UNCOMPRESSED) {
            return false; // not applicable for compressed point
        } else if (group == NamedGroup.ECDH_X25519 || group == NamedGroup.ECDH_X448) {
            return false; // not applicable for compressed point
        } else if (InvalidCurvePoint.fromNamedGroup(group) == null) {
            return false; // no suitable point configured
        } else {
            return true;
        }
    }

    private boolean legitTwistVector(NamedGroup group, ECPointFormat format) {
        if (TwistedCurvePoint.fromIntendedNamedGroup(group) == null) {
            return false; // no suitable point configured
        } else if (format == ECPointFormat.ANSIX962_COMPRESSED_PRIME
                && (group == NamedGroup.ECDH_X25519 || group == NamedGroup.ECDH_X448)) {
            // X-curves are neither uncompressed nor ANSIX962, we schedule them
            // as uncompressed as it is the default format (format is ignored)
            return false;
        } else {
            return true;
        }
    }

    /**
     * Picks one version for which we run scans in renegotiation
     */
    private ProtocolVersion pickRenegotiationVersion() {
        if (supportedProtocolVersions.contains(ProtocolVersion.TLS12) && supportsRenegotiation) {
            return ProtocolVersion.TLS12;
        } else if (supportedProtocolVersions.contains(ProtocolVersion.TLS11) && supportsRenegotiation) {
            return ProtocolVersion.TLS11;
        } else if (supportedProtocolVersions.contains(ProtocolVersion.TLS10) && supportsRenegotiation) {
            return ProtocolVersion.TLS10;
        } else if (supportedProtocolVersions.contains(ProtocolVersion.TLS13)
                && (issuesTls13SessionTickets == TestResult.TRUE && supportsTls13PskDhe == TestResult.TRUE)) {
            return ProtocolVersion.TLS13;
        }
        LOGGER.info("Could not find a suitable version for Invalid Curve renegotiation scans");
        return null;
    }

    /**
     * Select highest pre-Tls13 version and Tls13 if available
     */
    private List<ProtocolVersion> pickProtocolVersions() {
        List<ProtocolVersion> picked = new LinkedList<>();
        if (supportedProtocolVersions.contains(ProtocolVersion.TLS12)) {
            picked.add(ProtocolVersion.TLS12);
        } else if (supportedProtocolVersions.contains(ProtocolVersion.TLS11)) {
            picked.add(ProtocolVersion.TLS11);
        } else if (supportedProtocolVersions.contains(ProtocolVersion.TLS10)) {
            picked.add(ProtocolVersion.TLS10);
        }

        if (supportedProtocolVersions.contains(ProtocolVersion.TLS13)) {
            picked.add(ProtocolVersion.TLS13);
        }

        return picked;
    }

    /**
     * Groups ciphersuites per Version in a hopefully sensible way that reduces
     * the probe count but still provides enough accuracy
     */
    private HashMap<ProtocolVersion, List<CipherSuite>> filterCipherSuites(NamedGroup group) {
        HashMap<ProtocolVersion, List<CipherSuite>> groupedMap = new HashMap<>();
        for (ProtocolVersion protocolVersion : supportedProtocolVersions) {
            List<CipherSuite> coveredSuites = new LinkedList<CipherSuite>();
            boolean gotStatic = false;
            boolean gotEphemeral = false;
            boolean gotGCM = false;
            boolean gotCBC = false;
            boolean gotSHA = false;
            boolean gotSHA256 = false;
            boolean gotSHA384 = false;
            boolean gotSHA512 = false;
            boolean gotECDSA = false;
            boolean gotRSA = false;
            boolean gotWeak = false; // very wide ranged
            if (supportedECDHCipherSuites.get(protocolVersion) != null) {
                for (CipherSuite cipherSuite : supportedECDHCipherSuites.get(protocolVersion)) {
                    boolean addCandidate = false;
                    if (groupQualifiedForCiphersuite(group, cipherSuite)) {
                        if (!cipherSuite.isEphemeral() && gotStatic == false) {
                            addCandidate = true;
                            gotStatic = true;
                        }
                        if (cipherSuite.isEphemeral() && gotEphemeral == false) {
                            addCandidate = true;
                            gotEphemeral = true;
                        }

                        if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
                            if (cipherSuite.isGCM() && gotGCM == false) {
                                addCandidate = true;
                                gotGCM = true;
                            } else if (cipherSuite.isCBC() && gotCBC == false) {
                                addCandidate = true;
                                gotCBC = true;
                            }

                            if (cipherSuite.isSHA() && gotSHA == false) {
                                addCandidate = true;
                                gotSHA = true;
                            } else if (cipherSuite.isSHA256() && gotSHA256 == false) {
                                addCandidate = true;
                                gotSHA256 = true;
                            } else if (cipherSuite.isSHA384() && gotSHA384 == false) {
                                addCandidate = true;
                                gotSHA384 = true;
                            } else if (cipherSuite.isSHA512() && gotSHA512 == false) {
                                addCandidate = true;
                                gotSHA512 = true;
                            }

                            if (cipherSuite.isECDSA() && gotECDSA == false) {
                                addCandidate = true;
                                gotECDSA = true;
                            } else if (cipherSuite.name().contains("RSA") && gotRSA == false) {
                                addCandidate = true;
                                gotRSA = true;
                            }

                            if (cipherSuite.isWeak() && gotWeak == false) {
                                addCandidate = true;
                                gotWeak = true;
                            }
                        }
                        if (addCandidate) {
                            coveredSuites.add(cipherSuite);
                        }
                    }

                }
            }
            groupedMap.put(protocolVersion, coveredSuites);
        }

        return groupedMap;
    }

    private List<SignatureAndHashAlgorithm> getTls13SignatureAndHashAlgorithms() {
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
        return algos;
    }

    private boolean groupQualifiedForCiphersuite(NamedGroup testGroup, CipherSuite testCipher) {
        if (!testCipher.isTLS13()) {
            if (namedCurveWitnesses.containsKey(testGroup) == false) {
                return false;
            } else if ((testCipher.isRSA() && !namedCurveWitnesses.get(testGroup).getWitnessType().name()
                    .contains("RSA"))
                    || (testCipher.isECDSA() && testCipher.isEphemeral() && !namedCurveWitnesses.get(testGroup)
                            .getWitnessType().name().contains("EPHEMERAL"))
                    || (testCipher.isECDSA() && !testCipher.isEphemeral() && !namedCurveWitnesses.get(testGroup)
                            .getWitnessType().name().contains("STATIC"))) {
                return false;
            }
        }
        return true;
    }

    private List<NamedGroup> getRequiredGroups(NamedGroup testGroup, CipherSuite testCipher) {
        List<NamedGroup> requiredGroups = new LinkedList<>();
        if (testCipher.isTLS13()) {
            if (namedCurveWitnessesTls13.get(testGroup).getEcdsaPkGroupEphemeral() != null
                    && namedCurveWitnessesTls13.get(testGroup).getEcdsaPkGroupEphemeral() != testGroup) {
                requiredGroups.add(namedCurveWitnessesTls13.get(testGroup).getEcdsaPkGroupEphemeral());
            }
            if (namedCurveWitnessesTls13.get(testGroup).getEcdsaSigGroupEphemeral() != null
                    && namedCurveWitnessesTls13.get(testGroup).getEcdsaSigGroupEphemeral() != testGroup) {
                requiredGroups.add(namedCurveWitnessesTls13.get(testGroup).getEcdsaSigGroupEphemeral());
            }
        } else {
            // RSA ciphersuites don't require any additional groups
            if (testCipher.isECDSA() && testCipher.isEphemeral()) {
                if (namedCurveWitnesses.get(testGroup).getEcdsaPkGroupEphemeral() != testGroup) {
                    requiredGroups.add(namedCurveWitnesses.get(testGroup).getEcdsaPkGroupEphemeral());
                }
                if (namedCurveWitnesses.get(testGroup).getEcdsaSigGroupEphemeral() != null
                        && namedCurveWitnesses.get(testGroup).getEcdsaSigGroupEphemeral() != testGroup) {
                    requiredGroups.add(namedCurveWitnesses.get(testGroup).getEcdsaSigGroupEphemeral());
                }
            } else if (testCipher.isECDSA()) {
                if (namedCurveWitnesses.get(testGroup).getEcdsaPkGroupStatic() != testGroup) {
                    requiredGroups.add(namedCurveWitnesses.get(testGroup).getEcdsaPkGroupStatic());
                }
                if (namedCurveWitnesses.get(testGroup).getEcdsaSigGroupStatic() != null
                        && namedCurveWitnesses.get(testGroup).getEcdsaSigGroupStatic() != testGroup) {
                    requiredGroups.add(namedCurveWitnesses.get(testGroup).getEcdsaSigGroupStatic());
                }
            }
        }
        return requiredGroups;

    }

    private boolean benignHandshakeSuccessfull(InvalidCurveVector vector) {
        InvalidCurveAttackConfig dummyAttackConfig = new InvalidCurveAttackConfig(getScannerConfig()
                .getGeneralDelegate());
        InvalidCurveAttacker configBearer = prepareAttacker(dummyAttackConfig, vector.getProtocolVersion(),
                vector.getCipherSuiteAsList(), vector.getNamedGroup(), vector.getEcdsaRequiredGroups());
        Config tlsConfig = configBearer.getTlsConfig();
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        tlsConfig.setDefaultSelectedCipherSuite(vector.getCipherSuite());
        tlsConfig.setDefaultSelectedNamedGroup(vector.getNamedGroup());
        State state = new State(tlsConfig);
        executeState(state);

        if (!state.getWorkflowTrace().executedAsPlanned()) {
            LOGGER.warn("Benign handshake failed for " + vector.toString() + " - omitting from Invalid Curve");
            return false;
        } else if (state.getTlsContext().getSelectedGroup() != vector.getNamedGroup()) {
            LOGGER.warn("Benign handshake used wrong group (" + state.getTlsContext().getSelectedGroup() + ") for "
                    + vector.toString() + " - omitting from Invalid Curve");
            return false;
        }

        return true;
    }
    
    private boolean fingerprintsDiffer(InvalidCurveResponse scanResponse)
    {
        ResponseFingerprint firstFingerprint = null;
        for(FingerprintSecretPair pair : scanResponse.getFingerprintSecretPairs())
        {
            if(firstFingerprint == null && pair.getFingerprint() != null) {
                firstFingerprint = pair.getFingerprint();
            }
            else if(firstFingerprint != null) {
                if(pair.getFingerprint() != null && !pair.getFingerprint().toString().equals(firstFingerprint.toString())) {
                    return true;
                }
            }
        }
        
        return false;
    }
}
