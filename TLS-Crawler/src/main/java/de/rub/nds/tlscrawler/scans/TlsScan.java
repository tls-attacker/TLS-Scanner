/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.util.response.FingerprintSecretPair;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTarget;
import de.rub.nds.tlscrawler.data.ScanResult;
import de.rub.nds.tlsscanner.ScanJob;
import de.rub.nds.tlsscanner.ThreadedScanJobExecutor;
import de.rub.nds.tlsscanner.TlsScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.probe.CiphersuiteProbe;
import de.rub.nds.tlsscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.probe.certificate.CertificateIssue;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.probe.invalidCurve.InvalidCurveParameterSet;
import de.rub.nds.tlsscanner.probe.invalidCurve.InvalidCurveResponse;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.AnalyzedPropertyCategory;
import de.rub.nds.tlsscanner.report.PerformanceData;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.after.AfterProbe;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleCipherSuiteFingerprint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Scan using TLS Scanner, i. e. TLS Attacker.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class TlsScan implements IScan {

    private static Logger LOG = LoggerFactory.getLogger(TlsScan.class);

    private static String SCAN_NAME = "tls_scan";

    private final ParallelExecutor parallelExecutor;

    public TlsScan() {
        parallelExecutor = new ParallelExecutor(600, 5);
    }

    @Override
    public String getName() {
        return SCAN_NAME;
    }

    @Override
    public IScanResult scan(String slaveInstanceId, IScanTarget target) {
        LOG.trace("scan()");

        GeneralDelegate generalDelegate = new GeneralDelegate();
        generalDelegate.setQuiet(true);

        ScannerConfig config = new ScannerConfig(generalDelegate);
        config.setNoProgressbar(true);
        config.setScanDetail(ScannerDetail.NORMAL);
        config.setTimeout(1000);

        // TODO: Make port not hardcoded.
        int port = 443;
        config.getClientDelegate().setHost(target.getIp() + ":" + port);
        List<TlsProbe> probeList = new LinkedList<>();
        probeList.add(new CiphersuiteProbe(config, parallelExecutor));
        probeList.add(new ProtocolVersionProbe(config, parallelExecutor));
        List<AfterProbe> afterList = new LinkedList<>();
        
        // REMARK:  both of these two are replaced by the scanner
        //          the constructor still requires them
        ScanJob scanJob = new ScanJob(probeList, afterList);
        ThreadedScanJobExecutor executor = new ThreadedScanJobExecutor(config, scanJob, parallelExecutor.getSize(), config
                            .getClientDelegate().getHost());
        
        
        TlsScanner scanner = new TlsScanner(config, executor, parallelExecutor, probeList, afterList);
        SiteReport report = scanner.scan();

        IScanResult result = new ScanResult(SCAN_NAME);
        result.addString(SLAVE_INSTANCE_ID, slaveInstanceId);
        populateScanResultFromSiteReport(result, report);

        return result;
    }

    IScanResult populateScanResultFromSiteReport(IScanResult result, SiteReport report) {

        result.addString("host", report.getHost());
        result.addBoolean("serverIsAlive", report.getServerIsAlive());
        result.addBoolean("supportsSslTls", report.getSupportsSslTls());

        HashMap<AnalyzedPropertyCategory,ScanResult> categoryMap = new HashMap();
        for(AnalyzedPropertyCategory category : AnalyzedPropertyCategory.values()){
            categoryMap.put(category, new ScanResult(category.name()));
        }
        
        //add AnalyzedProperties
        for(String propertyKey : report.getResultMap().keySet()){
            AnalyzedProperty property = AnalyzedProperty.valueOf(propertyKey);
            categoryMap.get(property.getCategory()).addString(propertyKey, report.getResult(property).name());
        }
        
        for(AnalyzedPropertyCategory category : categoryMap.keySet()){
            result.addSubResult(category.name(), categoryMap.get(category));
        }

        List<String> _supportedCompressionMethods = new LinkedList<>();
        List<CompressionMethod> _rawSupportedCompressionMethods = report.getSupportedCompressionMethods();
        if (_rawSupportedCompressionMethods != null) {
            for (CompressionMethod x : _rawSupportedCompressionMethods) {
                _supportedCompressionMethods.add(x == null ? null : x.toString());
            }
        }

        result.addStringArray("supportedCompressionMethods", _supportedCompressionMethods);

        //kresult.addSubResult("rfc", getRfcPage(report));
        result.addSubResult("certificate", getCertificatePage(report));
        result.addSubResult("ciphers", getCiphersPage(report));
        result.addSubResult("gcm", getGcmPage(report));
        result.addSubResult("paddingOracle", getPaddingOraclePage(report));
        result.addSubResult("invalidCurve", getInvalidCurvePage(report));
        
        return result;
    }

    static IScanResult getPaddingOraclePage(SiteReport report) {
        IScanResult paddingOracle = new ScanResult("paddingOracle");

        List<PaddingOracleCipherSuiteFingerprint> _rawPaddingOracleresult = report.getPaddingOracleTestResultList();

        if (_rawPaddingOracleresult == null) {
            return null;
        }

        List<IScanResult> paddingOracleResults = new LinkedList<>();
        paddingOracle.addString("CVE", report.getKnownVulnerability() == null ? "none" : report.getKnownVulnerability().getCve());
        for (PaddingOracleCipherSuiteFingerprint potr : _rawPaddingOracleresult) {
            IScanResult tmp = new ScanResult("_paddingOracleResult");

            tmp.addString("getEqualityError", potr.getEqualityError().name());
            tmp.addString("recordGeneratorType", potr.getRecordGeneratorType().name());
            tmp.addString("vectorGeneratorType", potr.getVectorGeneratorType().name());
            tmp.addString("suite", potr.getSuite().name());
            tmp.addString("version", potr.getVersion().name());
            tmp.addBoolean("vulnerable", potr.getVulnerable());
            tmp.addBoolean("scanningError", potr.isHasScanningError());

            List<VectorResponse> fp = potr.getResponseMapList().size() > 0 ? potr.getResponseMapList().get(0) : new LinkedList<>();
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
    
    static IScanResult getInvalidCurvePage(SiteReport report) {
        IScanResult invalidCurve = new ScanResult("invalidCurve");
        if(report.getInvalidCurveResultList() != null)
        {
            List<IScanResult> scanResultList = new LinkedList<>();
            for(InvalidCurveResponse response : report.getInvalidCurveResultList())
            {
                IScanResult tmp = new ScanResult("_invalidCurveResult");
                
                //parameterSet
                InvalidCurveParameterSet paramSet = response.getParameterSet();
                
                List<String> cipherSuites = new LinkedList<>();
                for(CipherSuite cipherSuite : paramSet.getCipherSuites())
                {
                    cipherSuites.add(cipherSuite.name());
                }
                
                tmp.addStringArray("cipherSuites", cipherSuites);
                tmp.addString("pointFormat", paramSet.getPointFormat().name());
                tmp.addString("namedGroup", paramSet.getNamedGroup().name());
                tmp.addString("protocolVersion", paramSet.getProtocolVersion().name());
                tmp.addBoolean("twistAttack", paramSet.isTwistAttack());
                tmp.addBoolean("attackInRenegotiation", paramSet.isAttackInRenegotiation());
                
                //responses
                List<IScanResult> pairResultList = new LinkedList<>();
                for(FingerprintSecretPair fpsPair : response.getFingerprintSecretPairs())
                {
                    IScanResult resultPair = new ScanResult("_fingerprintSecretPair"); 
                    resultPair.addInteger("appliedSecret", fpsPair.getAppliedSecret());
                    resultPair.addString("responseFingerprint", fpsPair.getFingerprint().toString());
                    pairResultList.add(resultPair);
                }
                tmp.addSubResultArray("fingerprintSecretPairs", pairResultList);
                
                List<IScanResult> receivedPublicResultList = new LinkedList<>();
                for(Point point : response.getReceivedEcPublicKeys())
                {
                    IScanResult receivedPublic = new ScanResult("_receivedPublicKey");
                    receivedPublic.addString("x" , point.getX().getData().toString());
                    receivedPublic.addString("y" , point.getX().getData().toString());
                    receivedPublicResultList.add(receivedPublic);
                }
                tmp.addSubResultArray("receivedPublicKeys", receivedPublicResultList);
                
                List<IScanResult> finishedPublicResultList = new LinkedList<>();
                for(Point point : response.getReceivedFinishedEcKeys())
                {
                    IScanResult finishedPublic = new ScanResult("_receivedFinishedKey");
                    finishedPublic.addString("x" , point.getX().getData().toString());
                    finishedPublic.addString("y" , point.getX().getData().toString());
                    finishedPublicResultList.add(finishedPublic);
                }
                tmp.addSubResultArray("receivedFinishedKeys", finishedPublicResultList);
                
                //results
                tmp.addString("showsPointsAreNotValidated", response.getShowsPointsAreNotValidated().toString());
                tmp.addString("chosenGroupReusesKey", response.getChosenGroupReusesKey().toString());
                tmp.addString("dirtyKeysWarning", response.getDirtyKeysWarning().toString());
                tmp.addString("finishedReusedKey", response.getFinishedHandshakeHadReusedKey().toString());
                tmp.addString("showsVulnerability", response.getShowsVulnerability().toString());
                
                scanResultList.add(tmp);
            }
            invalidCurve.addSubResultArray("invalidCurveResults", scanResultList);    
        }
        return invalidCurve;
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
        
        List<String> _supportedTls13NamedCurves = new LinkedList<>();
        List<NamedGroup> _rawSupportedTls13NamedCurves = report.getSupportedTls13Groups();
        if (_rawSupportedTls13NamedCurves != null) {
            for (NamedGroup x : _rawSupportedTls13NamedCurves) {
                _supportedTls13NamedCurves.add(x == null ? null : x.toString());
            }
        }

        extensions.addStringArray("supportedTls13NamedCurves", _supportedTls13NamedCurves);

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
        if(report.getCertificateChain() != null)
        {
            CertificateChain chain = report.getCertificateChain();
        
            List<String> _certificateReports = new LinkedList<>();
            List<String> _certificateFingerprints = new LinkedList<>();
            List<CertificateReport> _rawCertificateReports = chain.getCertificateReportList();
            if (_rawCertificateReports != null) {
                for (CertificateReport x : _rawCertificateReports) {
                    _certificateReports.add(x == null ? null : x.toString());
                    _certificateFingerprints.add(x == null ? "" : x.getSHA256Fingerprint());
                }
            }

            certificate.addStringArray("certificateFingerprints", _certificateFingerprints);
            certificate.addStringArray("certificateReports", _certificateReports);
            certificate.addString("certificate", report.getCertificate() == null ? null : report.getCertificate().toString());
            certificate.addBoolean("certificateIsTrusted", chain.getGenerallyTrusted());
            
            List<String> issueList = new LinkedList<>();
            for(CertificateIssue issue : chain.getCertificateIssues())
            {
                issueList.add(issue.name());
            }
            certificate.addStringArray("certificateIssues", issueList);

        }
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
        return ciphers;
    }



    IScanResult getGcmPage(SiteReport report) {
        IScanResult gcm = new ScanResult("gcm");

        /*
        gcm.addBoolean("gcmReuse", report.getGcmReuse());
        gcm.addString("gcmPattern", report.getGcmPattern() == null ? null : report.getGcmPattern().name());
        gcm.addBoolean("gcmCheck", report.getGcmCheck());
        */
        return gcm;
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
