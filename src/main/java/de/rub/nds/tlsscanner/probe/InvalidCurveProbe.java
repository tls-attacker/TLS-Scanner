/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackConfig;
import de.rub.nds.tlsattacker.attacks.ec.InvalidCurvePoint;
import de.rub.nds.tlsattacker.attacks.ec.TwistedCurvePoint;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurveOverFp;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.probe.invalidCurve.InvalidCurveParameterSet;
import de.rub.nds.tlsscanner.probe.invalidCurve.InvalidCurveResponse;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.InvalidCurveResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class InvalidCurveProbe extends TlsProbe {

    private boolean supportsRenegotiation;

    private TestResult supportsSecureRenegotiation;

    private TestResult issuesTls13SessionTickets;

    private List<ProtocolVersion> supportedProtocolVersions;

    private List<NamedGroup> supportedFpGroups;

    private List<NamedGroup> supportedTls13FpGroups;

    private HashMap<ProtocolVersion, List<CipherSuite>> supportedECDHCipherSuites;

    private List<ECPointFormat> fpPointFormatsToTest;

    private List<ECPointFormat> tls13FpPointFormatsToTest;

    public InvalidCurveProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.INVALID_CURVE, config, 10);
    }

    @Override
    public ProbeResult executeTest() {
        List<InvalidCurveParameterSet> parameterSets = prepareParameterCombinations();
        List<InvalidCurveResponse> responses = new LinkedList<>();
        for (InvalidCurveParameterSet parameterSet : parameterSets) {
            InvalidCurveResponse scanResponse = executeSingleScan(parameterSet);
            if (scanResponse.getShowsPointsAreNotValidated() == TestResult.TRUE) {
                // rescan to reliably detect reused keys (especially TLS 1.3)
                InvalidCurveResponse rescanResponse = executeSingleScan(parameterSet);
                scanResponse.getReceivedEcPublicKeys().addAll(rescanResponse.getReceivedEcPublicKeys());
                scanResponse.getReceivedFinishedEcKeys().addAll(rescanResponse.getReceivedFinishedEcKeys());
            }
            responses.add(scanResponse);
        }
        return evaluateResponses(responses);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (report.getResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.NOT_TESTED_YET
                || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.NOT_TESTED_YET
                || report.getVersionSuitePairs() == null) {
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

        List<NamedGroup> groups = new LinkedList<>();
        if (report.getSupportedNamedGroups() != null) {
            for (NamedGroup group : report.getSupportedNamedGroups()) {
                if (NamedGroup.getImplemented().contains(group)
                        && CurveFactory.getCurve(group) instanceof EllipticCurveOverFp) {
                    groups.add(group);
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
                || scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
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
        if (report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.TRUE) {
            protocolVersions.add(ProtocolVersion.TLS13);
            List<NamedGroup> tls13groups = new LinkedList();
            for (NamedGroup group : report.getSupportedTls13Groups()) {
                if (NamedGroup.getImplemented().contains(group)
                        && CurveFactory.getCurve(group) instanceof EllipticCurveOverFp) {
                    tls13groups.add(group);
                }
            }

            List<CipherSuite> tls13CipherSuites = new LinkedList<>();
            for (CipherSuite cipherSuite : report.getSupportedTls13CipherSuites()) {
                if (cipherSuite.isImplemented()) {
                    tls13CipherSuites.add(cipherSuite);
                }
            }

            List<ECPointFormat> tls13FpPointFormats = new LinkedList<>();
            tls13FpPointFormats.add(ECPointFormat.UNCOMPRESSED);
            if (report.getResult(AnalyzedProperty.SUPPORTS_SECP_COMPRESSION_TLS13) == TestResult.TRUE) {
                tls13FpPointFormats.add(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
            }

            cipherSuitesMap.put(ProtocolVersion.TLS13, tls13CipherSuites);
            supportedTls13FpGroups = tls13groups;
            tls13FpPointFormatsToTest = tls13FpPointFormats;
        }

        fpPointFormatsToTest = fpPointFormats;
        supportedProtocolVersions = protocolVersions;
        supportedFpGroups = groups;
        supportedECDHCipherSuites = cipherSuitesMap;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new InvalidCurveResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST,
                null);
    }

    private InvalidCurveAttacker prepareAttacker(InvalidCurveAttackConfig attackConfig,
            ProtocolVersion protocolVersion, List<CipherSuite> cipherSuites, NamedGroup group) {
        ClientDelegate delegate = (ClientDelegate) attackConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        StarttlsDelegate starttlsDelegate = (StarttlsDelegate) attackConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
        InvalidCurveAttacker attacker = new InvalidCurveAttacker(attackConfig, attackConfig.createConfig(),
                getParallelExecutor());

        if (protocolVersion == ProtocolVersion.TLS13) {
            attacker.getTlsConfig().setAddKeyShareExtension(true);
            attacker.getTlsConfig().setAddECPointFormatExtension(false);
            attacker.getTlsConfig().setAddSupportedVersionsExtension(true);
            attacker.getTlsConfig().setAddPSKKeyExchangeModesExtension(true);
            List<PskKeyExchangeMode> pskKex = new LinkedList<>();
            pskKex.add(PskKeyExchangeMode.PSK_DHE_KE);
            attacker.getTlsConfig().setPSKKeyExchangeModes(pskKex);
        }

        attacker.getTlsConfig().setHighestProtocolVersion(protocolVersion);
        attacker.getTlsConfig().setDefaultSelectedProtocolVersion(protocolVersion);
        attacker.getTlsConfig().setDefaultClientSupportedCiphersuites(cipherSuites);
        attacker.getTlsConfig().setDefaultClientNamedGroups(group);
        attacker.getTlsConfig().setDefaultSelectedNamedGroup(group);
        if (supportsSecureRenegotiation == TestResult.TRUE) {
            attacker.getTlsConfig().setAddRenegotiationInfoExtension(true);
        } else {
            attacker.getTlsConfig().setAddRenegotiationInfoExtension(false);
        }
        return attacker;
    }

    private List<InvalidCurveParameterSet> prepareParameterCombinations() {
        LinkedList<InvalidCurveParameterSet> parameterSets = new LinkedList<>();

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
                        if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
                            // individual scans for every ciphersuite
                            for (CipherSuite cipherSuite : supportedECDHCipherSuites.get(protocolVersion)) {
                                if (legitInvalidCurveVector(group, format)) {
                                    parameterSets.add(new InvalidCurveParameterSet(protocolVersion, cipherSuite, group,
                                            format, false, false));
                                }
                                if (legitTwistVector(group, format)) {
                                    parameterSets.add(new InvalidCurveParameterSet(protocolVersion, cipherSuite, group,
                                            format, true, false));
                                }
                            }
                        } else {
                            // split ciphersuites in static and ephemeral and
                            // scan
                            // once for each list
                            LinkedList<CipherSuite> ephemeralSuites = new LinkedList<>();
                            LinkedList<CipherSuite> staticSuites = new LinkedList<>();
                            for (CipherSuite cipherSuite : supportedECDHCipherSuites.get(protocolVersion)) {
                                if (cipherSuite.isEphemeral()) {
                                    ephemeralSuites.add(cipherSuite);
                                } else {
                                    staticSuites.add(cipherSuite);
                                }
                            }

                            if (ephemeralSuites.size() > 0) {
                                if (legitInvalidCurveVector(group, format)) {
                                    parameterSets.add(new InvalidCurveParameterSet(protocolVersion, ephemeralSuites,
                                            group, format, false, false));
                                }
                                if (legitTwistVector(group, format)) {
                                    parameterSets.add(new InvalidCurveParameterSet(protocolVersion, ephemeralSuites,
                                            group, format, true, false));
                                }
                            }
                            if (staticSuites.size() > 0) {
                                if (legitInvalidCurveVector(group, format)) {
                                    parameterSets.add(new InvalidCurveParameterSet(protocolVersion, staticSuites,
                                            group, format, false, false));
                                }
                                if (legitTwistVector(group, format)) {
                                    parameterSets.add(new InvalidCurveParameterSet(protocolVersion, staticSuites,
                                            group, format, true, false));
                                }
                            }
                        }

                    }
                }

            }
        }

        // repeat scans in renegotiation
        if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL)) {
            int setCount = parameterSets.size();
            for (int i = 0; i < setCount; i++) {
                InvalidCurveParameterSet set = parameterSets.get(i);
                if ((set.getProtocolVersion() == ProtocolVersion.TLS13 && issuesTls13SessionTickets == TestResult.TRUE)
                        || supportsRenegotiation) {
                    parameterSets.add(new InvalidCurveParameterSet(set.getProtocolVersion(), set.getCipherSuites(), set
                            .getNamedGroup(), set.getPointFormat(), set.isTwistAttack(), true));
                }
            }
        }
        return parameterSets;
    }

    private InvalidCurveResponse executeSingleScan(InvalidCurveParameterSet parameterSet) {
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
                    invalidCurveAttackConfig.setProtocolFlows(TwistedCurvePoint
                            .fromIntendedNamedGroup(parameterSet.getNamedGroup()).getOrder().intValue() * 2);
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
                invalidCurveAttackConfig.setProtocolFlows(InvalidCurvePoint
                        .fromNamedGroup(parameterSet.getNamedGroup()).getOrder().intValue() * 2);
                invalidCurveAttackConfig.setPointCompressionFormat(ECPointFormat.UNCOMPRESSED);
            }

            InvalidCurveAttacker attacker = prepareAttacker(invalidCurveAttackConfig,
                    parameterSet.getProtocolVersion(), parameterSet.getCipherSuites(), parameterSet.getNamedGroup());
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
                    if (response.getParameterSet().getCipherSuites().get(0).isEphemeral()) {
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
            return false; // format is *pointless*
        } else {
            return true;
        }
    }
}
