/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTarget;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlsscanner.SingleThreadedScanJobExecutor;
import de.rub.nds.tlsscanner.TlsScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.probe.CiphersuiteProbe;
import de.rub.nds.tlsscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.report.PerformanceData;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.after.AfterProbe;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleTestResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Scan using TLS Scanner, i. e. TLS Attacker.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TlsScan implements IScan {

    private static Logger LOG = LoggerFactory.getLogger(TlsScan.class);

    private static String SCAN_NAME = "tls_scan";

    private ParallelExecutor parallelExecutor;

    public TlsScan() {
        parallelExecutor = new ParallelExecutor(400, 3);
    }

    @Override
    public String getName() {
        return SCAN_NAME;
    }

    @Override
    public IScanResult scan(String slaveInstanceId, IScanTarget target) {
        LOG.trace("scan()");

        SingleThreadedScanJobExecutor executor = new SingleThreadedScanJobExecutor();

        GeneralDelegate generalDelegate = new GeneralDelegate();
        generalDelegate.setQuiet(true);

        ScannerConfig config = new ScannerConfig(generalDelegate);
        config.setNoProgressbar(true);
        config.setScanDetail(ScannerDetail.DETAILED);
        // TODO: Make port not hardcoded.
        int port = 443;
        config.getClientDelegate().setHost(target.getIp() + ":" + port);
        List<TlsProbe> phaseOneList = new LinkedList<>();
        phaseOneList.add(new CiphersuiteProbe(config, parallelExecutor));
        phaseOneList.add(new ProtocolVersionProbe(config, parallelExecutor));
        List<TlsProbe> phaseTwoList = new LinkedList<>();

        phaseTwoList.add(new PaddingOracleProbe(config, parallelExecutor));
        List<AfterProbe> afterList = new LinkedList<>();
        TlsScanner scanner = new TlsScanner(config, executor, parallelExecutor, phaseOneList, phaseTwoList, afterList);
        SiteReport report = scanner.scan();

        IScanResult result = new ScanResult(SCAN_NAME);
        result.addString(SLAVE_INSTANCE_ID, slaveInstanceId);
        populateScanResultFromSiteReport(result, report);

        return result;
    }

    static IScanResult populateScanResultFromSiteReport(IScanResult result, SiteReport report) {
        result.addString("host", report.getHost());
        result.addBoolean("serverIsAlive", report.getServerIsAlive());
        result.addBoolean("supportsSslTls", report.getSupportsSslTls());

        result.addSubResult("attacks", getAttacksPage(report));
        result.addSubResult("version", getVersionPage(report));
        result.addSubResult("extensions", getExtensionsPage(report));

        List<String> _supportedCompressionMethods = new LinkedList<>();
        List<CompressionMethod> _rawSupportedCompressionMethods = report.getSupportedCompressionMethods();
        if (_rawSupportedCompressionMethods != null) {
            for (CompressionMethod x : _rawSupportedCompressionMethods) {
                _supportedCompressionMethods.add(x == null ? null : x.toString());
            }
        }

        result.addStringArray("supportedCompressionMethods", _supportedCompressionMethods);

        result.addSubResult("rfc", getRfcPage(report));
        result.addSubResult("certificate", getCertificatePage(report));
        result.addSubResult("ciphers", getCiphersPage(report));
        result.addSubResult("session", getSessionPage(report));
        result.addSubResult("renegotiation", getRenegotiationPage(report));
        result.addSubResult("gcm", getGcmPage(report));
        result.addSubResult("intolerances", getIntolerancesPage(report));
        result.addSubResult("performance", getPerformancePage(report));
        result.addSubResult("paddingOracle", getPaddingOraclePage(report));

        return result;
    }

    static IScanResult getAttacksPage(SiteReport report) {
        IScanResult attacks = new ScanResult("attacks");

        attacks.addBoolean("bleichenbacherVulnerable", report.getBleichenbacherVulnerable());
        attacks.addBoolean("paddingOracleVulnerable", report.getPaddingOracleVulnerable());
        attacks.addBoolean("invalidCurveVulnerable", report.getInvalidCurveVulnerable());
        attacks.addBoolean("invalidCurveEphermaralVulnerable", report.getInvalidCurveEphermaralVulnerable());
        attacks.addBoolean("poodleVulnerable", report.getPoodleVulnerable());
        attacks.addBoolean("tlsPoodleVulnerable", report.getTlsPoodleVulnerable());
        attacks.addBoolean("cve20162107Vulnerable", report.getCve20162107Vulnerable());
        attacks.addBoolean("crimeVulnerable", report.getCrimeVulnerable());
        attacks.addBoolean("breachVulnerable", report.getBreachVulnerable());
        attacks.addBoolean("sweet32Vulnerable", report.getSweet32Vulnerable());
        attacks.addString("drownVulnerable", report.getDrownVulnerable() != null ? report.getDrownVulnerable().name() : "");
        attacks.addBoolean("logjamVulnerable", report.getLogjamVulnerable());
        attacks.addBoolean("heartbleedVulnerable", report.getHeartbleedVulnerable());
        attacks.addString("earlyCcsVulnerable", report.getEarlyCcsVulnerable() != null ? report.getEarlyCcsVulnerable().name() : "");

        return attacks;
    }

    static IScanResult getPaddingOraclePage(SiteReport report) {
        IScanResult paddingOracle = new ScanResult("paddingOracle");

        List<PaddingOracleTestResult> _rawPaddingOracleresult = report.getPaddingOracleTestResultList();

        if (_rawPaddingOracleresult == null) {
            return null;
        }

        List<IScanResult> paddingOracleResults = new LinkedList<>();

        for (PaddingOracleTestResult potr : _rawPaddingOracleresult) {
            IScanResult tmp = new ScanResult("_paddingOracleResult");

            tmp.addString("getEqualityError", potr.getEqualityError().name());
            tmp.addString("recordGeneratorType", potr.getRecordGeneratorType().name());
            tmp.addString("vectorGeneratorType", potr.getVectorGeneratorType().name());
            tmp.addString("suite", potr.getSuite().name());
            tmp.addString("version", potr.getVersion().name());
            tmp.addBoolean("vulnerable", potr.getVulnerable());

            /*
            List<IScanResult> map = new LinkedList<>();
            for (Integer i : potr.getResponseMap().keySet()) {
                IScanResult response = new ScanResult(i.toString());

                List<ResponseFingerprint> fingerprints = potr.getResponseMap().get(i);

                response.addStringArray("responseFingerprint",
                        fingerprints.stream()
                                .map(ResponseFingerprint::toString)
                                .collect(Collectors.toList()));
            }
             */
            List<VectorResponse> fp = potr.getResponseMap().size() > 0 ? potr.getResponseMap() : new LinkedList<>();
            List<String> fp_toString = fp.stream()
                    .map(VectorResponse::toString)
                    .collect(Collectors.toList());

            tmp.addStringArray("responseMap", fp_toString);
            tmp.addBoolean("shaky", potr.isShakyScans());
            tmp.addBoolean("scanError", potr.isHasScanningError());
            paddingOracleResults.add(tmp);
        }

        paddingOracle.addSubResultArray("paddingOracleResults", paddingOracleResults);

        return paddingOracle;
    }

    static IScanResult getVersionPage(SiteReport report) {
        IScanResult version = new ScanResult("version");

        List<String> _versions = new LinkedList<>();
        List<ProtocolVersion> _rawVersions = report.getVersions();
        if (_rawVersions != null) {
            for (ProtocolVersion x : _rawVersions) {
                _versions.add(x == null ? null : x.toString());
            }
        }

        version.addStringArray("versions", _versions);
        version.addBoolean("supportsSsl2", report.getSupportsSsl2());
        version.addBoolean("supportsSsl3", report.getSupportsSsl3());
        version.addBoolean("supportsTls10", report.getSupportsTls10());
        version.addBoolean("supportsTls11", report.getSupportsTls11());
        version.addBoolean("supportsTls12", report.getSupportsTls12());
        version.addBoolean("supportsTls13", report.getSupportsTls13());
        version.addBoolean("supportsTls13Draft14", report.getSupportsTls13Draft14());
        version.addBoolean("supportsTls13Draft15", report.getSupportsTls13Draft15());
        version.addBoolean("supportsTls13Draft16", report.getSupportsTls13Draft16());
        version.addBoolean("supportsTls13Draft17", report.getSupportsTls13Draft17());
        version.addBoolean("supportsTls13Draft18", report.getSupportsTls13Draft18());
        version.addBoolean("supportsTls13Draft19", report.getSupportsTls13Draft19());
        version.addBoolean("supportsTls13Draft20", report.getSupportsTls13Draft20());
        version.addBoolean("supportsTls13Draft21", report.getSupportsTls13Draft21());
        version.addBoolean("supportsTls13Draft22", report.getSupportsTls13Draft22());
        version.addBoolean("supportsDtls10", report.getSupportsDtls10());
        version.addBoolean("supportsDtls12", report.getSupportsDtls12());
        version.addBoolean("supportsDtls13", report.getSupportsDtls13());

        return version;
    }

    static IScanResult getExtensionsPage(SiteReport report) {
        IScanResult extensions = new ScanResult("extensions");

        List<String> _supportedExtensions = new LinkedList<>();
        List<ExtensionType> _rawSupportedExtensions = report.getSupportedExtensions();
        if (_rawSupportedExtensions != null) {
            for (ExtensionType x : _rawSupportedExtensions) {
                _supportedExtensions.add(x == null ? null : x.toString());
            }
        }

        extensions.addStringArray("supportedExtensions", _supportedExtensions);

        List<String> _supportedNamedCurves = new LinkedList<>();
        List<NamedGroup> _rawSupportedNamedCurves = report.getSupportedNamedGroups();
        if (_rawSupportedNamedCurves != null) {
            for (NamedGroup x : _rawSupportedNamedCurves) {
                _supportedNamedCurves.add(x == null ? null : x.toString());
            }
        }

        extensions.addStringArray("supportedNamedCurves", _supportedNamedCurves);

        List<String> _supportedSignatureAndHashAlgorithms = new LinkedList<>();
        List<SignatureAndHashAlgorithm> _rawSupportedSignatureAndHashAlgorithms = report.getSupportedSignatureAndHashAlgorithms();
        if (_rawSupportedSignatureAndHashAlgorithms != null) {
            for (SignatureAndHashAlgorithm x : _rawSupportedSignatureAndHashAlgorithms) {
                _supportedSignatureAndHashAlgorithms.add(x == null ? null : x.toString());
            }
        }

        extensions.addStringArray("supportedSignatureAndHashAlgorithms", _supportedSignatureAndHashAlgorithms);

        List<String> _supportedTokenBindingVersion = new LinkedList<>();
        List<TokenBindingVersion> _rawSupportedTokenBindingVersion = report.getSupportedTokenBindingVersion();
        if (_rawSupportedTokenBindingVersion != null) {
            for (TokenBindingVersion x : _rawSupportedTokenBindingVersion) {
                _supportedTokenBindingVersion.add(x == null ? null : x.toString());
            }
        }

        extensions.addStringArray("supportedTokenBindingVersion", _supportedTokenBindingVersion);

        List<String> _supportedTokenBindingKeyParameters = new LinkedList<>();
        List<TokenBindingKeyParameters> _rawSupportedTokenBindingKeyParameters = report.getSupportedTokenBindingKeyParameters();
        if (_rawSupportedTokenBindingKeyParameters != null) {
            for (TokenBindingKeyParameters x : _rawSupportedTokenBindingKeyParameters) {
                _supportedTokenBindingKeyParameters.add(x == null ? null : x.toString());
            }
        }

        extensions.addStringArray("supportedTokenBindingKeyParameters", _supportedTokenBindingKeyParameters);

        extensions.addBoolean("supportsExtendedMasterSecret", report.getSupportsExtendedMasterSecret());
        extensions.addBoolean("supportsEncryptThenMacSecret", report.getSupportsEncryptThenMacSecret());
        extensions.addBoolean("supportsTokenbinding", report.getSupportsTokenbinding());

        return extensions;
    }

    static IScanResult getRfcPage(SiteReport report) {
        IScanResult rfc = new ScanResult("rfc");

        rfc.addString("macCheckPatternAppData", report.getMacCheckPatternAppData() != null ? report.getMacCheckPatternAppData().toString() : "");
        rfc.addString("macCheckPatternFinished", report.getMacCheckPatternFinished() != null ? report.getMacCheckPatternFinished().toString() : "");
        rfc.addString("checksFinished", report.getVerifyCheckPattern() != null ? report.getVerifyCheckPattern().getType().toString() : "");

        return rfc;
    }

    static IScanResult getCertificatePage(SiteReport report) {
        IScanResult certificate = new ScanResult("certificate");

        List<String> _certificateReports = new LinkedList<>();
        List<String> _certificateFingerprints = new LinkedList<>();
        List<CertificateReport> _rawCertificateReports = report.getCertificateReports();
        if (_rawCertificateReports != null) {
            for (CertificateReport x : _rawCertificateReports) {
                _certificateReports.add(x == null ? null : x.toString());
                _certificateFingerprints.add(x == null ? "" : x.getSHA256Fingerprint());
            }
        }

        certificate.addStringArray("certificateFingerprints", _certificateFingerprints);
        certificate.addStringArray("certificateReports", _certificateReports);
        certificate.addString("certificate", report.getCertificate() == null ? null : report.getCertificate().toString());
        certificate.addBoolean("certificateExpired", report.getCertificateExpired());
        certificate.addBoolean("certificateNotYetValid", report.getCertificateNotYetValid());
        certificate.addBoolean("certificateHasWeakHashAlgorithm", report.getCertificateHasWeakHashAlgorithm());
        certificate.addBoolean("certificateHasWeakSignAlgorithm", report.getCertificateHasWeakSignAlgorithm());
        certificate.addBoolean("certificateMachtesDomainName", report.getCertificateMachtesDomainName());
        certificate.addBoolean("certificateIsTrusted", report.getCertificateIsTrusted());
        certificate.addBoolean("certificateKeyIsBlacklisted", report.getCertificateKeyIsBlacklisted());

        return certificate;
    }

    static IScanResult getCiphersPage(SiteReport report) {
        IScanResult ciphers = new ScanResult("ciphers");

        List<String> _versionSuitePairs = new LinkedList<>();
        List<VersionSuiteListPair> _rawVersionSuitePairs = report.getVersionSuitePairs();
        if (_rawVersionSuitePairs != null) {
            for (VersionSuiteListPair x : _rawVersionSuitePairs) {
                _versionSuitePairs.add(x == null ? null : x.toString());
            }
        }

        ciphers.addStringArray("versionSuitePairs", _versionSuitePairs);

        List<String> _cipherSuites = new LinkedList<>();
        Collection<CipherSuite> _rawCipherSuites = report.getCipherSuites();
        if (_rawCipherSuites != null) {
            for (CipherSuite x : _rawCipherSuites) {
                _cipherSuites.add(x == null ? null : x.toString());
            }
        }

        ciphers.addStringArray("cipherSuites", _cipherSuites);
        ciphers.addBoolean("supportsNullCiphers", report.getSupportsNullCiphers());
        ciphers.addBoolean("supportsAnonCiphers", report.getSupportsAnonCiphers());
        ciphers.addBoolean("supportsExportCiphers", report.getSupportsExportCiphers());
        ciphers.addBoolean("supportsDesCiphers", report.getSupportsDesCiphers());
        ciphers.addBoolean("supportsSeedCiphers", report.getSupportsSeedCiphers());
        ciphers.addBoolean("supportsIdeaCiphers", report.getSupportsIdeaCiphers());
        ciphers.addBoolean("supportsRc2Ciphers", report.getSupportsRc2Ciphers());
        ciphers.addBoolean("supportsRc4Ciphers", report.getSupportsRc4Ciphers());
        ciphers.addBoolean("supportsTrippleDesCiphers", report.getSupportsTrippleDesCiphers());
        ciphers.addBoolean("supportsPostQuantumCiphers", report.getSupportsPostQuantumCiphers());
        ciphers.addBoolean("supportsAeadCiphers", report.getSupportsAeadCiphers());
        ciphers.addBoolean("supportsPfsCiphers", report.getSupportsPfsCiphers());
        ciphers.addBoolean("supportsOnlyPfsCiphers", report.getSupportsOnlyPfsCiphers());
        ciphers.addBoolean("enforcesCipherSuiteOrdering", report.getEnforcesCipherSuiteOrdering());
        ciphers.addBoolean("supportsAes", report.getSupportsAes());
        ciphers.addBoolean("supportsCamellia", report.getSupportsCamellia());
        ciphers.addBoolean("supportsAria", report.getSupportsAria());
        ciphers.addBoolean("supportsChacha", report.getSupportsChacha());
        ciphers.addBoolean("supportsRsa", report.getSupportsPskRsa());
        ciphers.addBoolean("supportsDh", report.getSupportsDh());
        ciphers.addBoolean("supportsEcdh", report.getSupportsEcdh());
        ciphers.addBoolean("supportsGost", report.getSupportsGost());
        ciphers.addBoolean("supportsSrp", report.getSupportsSrp());
        ciphers.addBoolean("supportsKerberos", report.getSupportsKerberos());
        ciphers.addBoolean("supportsPskPlain", report.getSupportsPskPlain());
        ciphers.addBoolean("supportsPskRsa", report.getSupportsPskRsa());
        ciphers.addBoolean("supportsPskDhe", report.getSupportsPskDhe());
        ciphers.addBoolean("supportsPskEcdhe", report.getSupportsPskEcdhe());
        ciphers.addBoolean("supportsFortezza", report.getSupportsFortezza());
        ciphers.addBoolean("supportsNewHope", report.getSupportsNewHope());
        ciphers.addBoolean("supportsEcmqv", report.getSupportsEcmqv());
        ciphers.addBoolean("prefersPfsCiphers", report.getPrefersPfsCiphers());
        ciphers.addBoolean("supportsStreamCiphers", report.getSupportsStreamCiphers());
        ciphers.addBoolean("supportsBlockCiphers", report.getSupportsBlockCiphers());

        return ciphers;
    }

    static IScanResult getSessionPage(SiteReport report) {
        IScanResult session = new ScanResult("session");

        session.addBoolean("supportsSessionTicket", report.getSupportsSessionTicket());
        session.addBoolean("supportsSessionIds", report.getSupportsSessionIds());
        session.addLong("sessionTicketLengthHint", report.getSessionTicketLengthHint());
        session.addBoolean("sessionTicketGetsRotated", report.getSupportsSessionTicket());
        session.addBoolean("vulnerableTicketBleed", report.getSupportsSessionTicket());

        return session;
    }

    static IScanResult getRenegotiationPage(SiteReport report) {
        IScanResult renegotiation = new ScanResult("renegotiation");

        renegotiation.addBoolean("supportsSecureRenegotiation", report.getSupportsSecureRenegotiation());
        renegotiation.addBoolean("supportsClientSideSecureRenegotiation", report.getSupportsClientSideSecureRenegotiation());
        renegotiation.addBoolean("supportsClientSideInsecureRenegotiation", report.getSupportsClientSideInsecureRenegotiation());
        renegotiation.addBoolean("tlsFallbackSCSVsupported", report.getTlsFallbackSCSVsupported());

        return renegotiation;
    }

    static IScanResult getGcmPage(SiteReport report) {
        IScanResult gcm = new ScanResult("gcm");

        gcm.addBoolean("gcmReuse", report.getGcmReuse());
        gcm.addString("gcmPattern", report.getGcmPattern() == null ? null : report.getGcmPattern().name());
        gcm.addBoolean("gcmCheck", report.getGcmCheck());

        return gcm;
    }

    static IScanResult getIntolerancesPage(SiteReport report) {
        IScanResult intolerances = new ScanResult("intolerances");

        intolerances.addBoolean("versionIntolerance", report.getVersionIntolerance());
        intolerances.addBoolean("extensionIntolerance", report.getExtensionIntolerance());
        intolerances.addBoolean("cipherSuiteIntolerance", report.getCipherSuiteIntolerance());
        intolerances.addBoolean("clientHelloLengthIntolerance", report.getClientHelloLengthIntolerance());

        return intolerances;
    }

    static IScanResult getPerformancePage(SiteReport report) {
        IScanResult performance = new ScanResult("performance");

        Collection<PerformanceData> _perfData = report.getPerformanceList();
        for (PerformanceData data : _perfData) {
            IScanResult perfDataPoint = new ScanResult(data.getType().name());
            perfDataPoint.addTimestamp("Starttime", Instant.ofEpochMilli(data.getStarttime()));
            perfDataPoint.addTimestamp("Stoptime", Instant.ofEpochMilli(data.getStoptime()));

            performance.addSubResult(data.getType().name(), perfDataPoint);
        }

        return performance;
    }
}
