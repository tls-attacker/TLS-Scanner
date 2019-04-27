/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTarget;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlsscanner.TlsScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Scan using TLS Scanner, i. e. TLS Attacker.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TlsScan implements IScan {
    private static Logger LOG = LoggerFactory.getLogger(TlsScan.class);

    private static String SCAN_NAME = "tls_scan";

    @Override
    public String getName() {
        return SCAN_NAME;
    }

    @Override
    public IScanResult scan(IScanTarget target) {
        LOG.trace("scan()");

        GeneralDelegate generalDelegate = new GeneralDelegate();
   //     generalDelegate.setLogLevel(null);

        ScannerConfig config = new ScannerConfig(generalDelegate);
        config.setThreads(1);

        int port = 443;
        config.getClientDelegate().setHost(target.getIp() + ":" + port);

        TlsScanner scanner = new TlsScanner(config);

        SiteReport report = scanner.scan();

        return scanResultFromSiteReport(report, SCAN_NAME);
    }

    IScanResult scanResultFromSiteReport(SiteReport report, String scanName) {
        IScanResult result = new ScanResult(scanName);

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

        return result;
    }

    IScanResult getAttacksPage(SiteReport report) {
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
        attacks.addDrownVulnerabilityType("drownVulnerable", report.getDrownVulnerable());
        attacks.addBoolean("logjamVulnerable", report.getLogjamVulnerable());
      //  attacks.addBoolean("lucky13Vulnerable", report.getLucky13Vulnerable());
        attacks.addBoolean("heartbleedVulnerable", report.getHeartbleedVulnerable());
        attacks.addEarlyCcsVulnerabilityType("earlyCcsVulnerable", report.getEarlyCcsVulnerable());

        return attacks;
    }

    IScanResult getVersionPage(SiteReport report) {
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

    IScanResult getExtensionsPage(SiteReport report) {
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

    IScanResult getRfcPage(SiteReport report) {
        IScanResult rfc = new ScanResult("rfc");

        rfc.addString("checksMac", report.getMacCheckPatternAppData().toString());
        rfc.addString("checksFinished", report.getVerifyCheckPattern().toString());

        return rfc;
    }

    IScanResult getCertificatePage(SiteReport report) {
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

    IScanResult getCiphersPage(SiteReport report) {
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
        Set<CipherSuite> _rawCipherSuites = report.getCipherSuites();
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

    IScanResult getSessionPage(SiteReport report) {
        IScanResult session = new ScanResult("session");

        session.addBoolean("supportsSessionTicket", report.getSupportsSessionTicket());
        session.addBoolean("supportsSessionIds", report.getSupportsSessionIds());
        session.addLong("sessionTicketLengthHint", report.getSessionTicketLengthHint());
        session.addBoolean("sessionTicketGetsRotated", report.getSupportsSessionTicket());
        session.addBoolean("vulnerableTicketBleed", report.getSupportsSessionTicket());

        return session;
    }

    IScanResult getRenegotiationPage(SiteReport report) {
        IScanResult renegotiation = new ScanResult("renegotiation");

        renegotiation.addBoolean("supportsSecureRenegotiation", report.getSupportsSecureRenegotiation());
        renegotiation.addBoolean("supportsClientSideSecureRenegotiation", report.getSupportsClientSideSecureRenegotiation());
        renegotiation.addBoolean("supportsClientSideInsecureRenegotiation", report.getSupportsClientSideInsecureRenegotiation());
        renegotiation.addBoolean("tlsFallbackSCSVsupported", report.getTlsFallbackSCSVsupported());

        return renegotiation;
    }

    IScanResult getGcmPage(SiteReport report) {
        IScanResult gcm = new ScanResult("gcm");

        gcm.addBoolean("gcmReuse", report.getGcmReuse());
        gcm.addString("gcmPattern", report.getGcmPattern() == null ? null : report.getGcmPattern().name());
        gcm.addBoolean("gcmCheck", report.getGcmCheck());

        return gcm;
    }

    IScanResult getIntolerancesPage(SiteReport report) {
        IScanResult intolerances = new ScanResult("intolerances");

        intolerances.addBoolean("versionIntolerance", report.getVersionIntolerance());
        intolerances.addBoolean("extensionIntolerance", report.getExtensionIntolerance());
        intolerances.addBoolean("cipherSuiteIntolerance", report.getCipherSuiteIntolerance());
        intolerances.addBoolean("clientHelloSizeIntolerance", report.getClientHelloLengthIntolerance());

        return intolerances;
    }
}
