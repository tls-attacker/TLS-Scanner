/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report;

import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.constants.GcmPattern;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClient;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleTestResult;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SiteReport {

    //General
    private final List<ProbeType> probeTypeList;
    private List<PerformanceData> performanceList;

    private final String host;
    private Boolean serverIsAlive = null;
    private Boolean supportsSslTls = null;

    //Quirks
    private Boolean requiresSni = null;

    //common bugs
    private Boolean extensionIntolerance; //does it handle unknown extenstions correctly?
    private Boolean versionIntolerance; //does it handle unknown versions correctly?
    private Boolean cipherSuiteIntolerance; //does it handle unknown ciphersuites correctly?
    private Boolean cipherSuiteLengthIntolerance512; //does it handle long ciphersuite length values correctly?
    private Boolean compressionIntolerance; //does it handle unknown compression algorithms correctly
    private Boolean alpnIntolerance; //does it handle unknown alpn strings correctly?
    private Boolean clientHelloLengthIntolerance; // 256 - 511 <-- ch should be bigger than this
    private Boolean namedGroupIntolerant; // does it handle unknown groups correctly
    private Boolean emptyLastExtensionIntolerance; //does it break on empty last extension
    private Boolean namedSignatureAndHashAlgorithmIntolerance; // does it handle signature and hash algorithms correctly
    private Boolean maxLengthClientHelloIntolerant; // server does not like really big client hello messages
    private Boolean onlySecondCiphersuiteByteEvaluated; //is only the second byte of the ciphersuite evaluated
    private Boolean ignoresCipherSuiteOffering; //does it ignore the offered ciphersuites
    private Boolean reflectsCipherSuiteOffering; //does it ignore the offered ciphersuites
    private Boolean ignoresOfferedNamedGroups; //does it ignore the offered named groups
    private Boolean ignoresOfferedSignatureAndHashAlgorithms; //does it ignore the sig hash algorithms

    //Attacks
    private Boolean bleichenbacherVulnerable = null;
    private Boolean paddingOracleVulnerable = null;
    private List<PaddingOracleTestResult> paddingOracleTestResultList;
    private Boolean invalidCurveVulnerable = null;
    private Boolean invalidCurveEphermaralVulnerable = null;
    private Boolean poodleVulnerable = null;
    private Boolean tlsPoodleVulnerable = null;
    private Boolean cve20162107Vulnerable = null;
    private Boolean crimeVulnerable = null;
    private Boolean breachVulnerable = null;
    private Boolean sweet32Vulnerable = null;
    private DrownVulnerabilityType drownVulnerable = null;
    private Boolean logjamVulnerable = null;
    private Boolean heartbleedVulnerable = null;
    private EarlyCcsVulnerabilityType earlyCcsVulnerable = null;
    private Boolean freakVulnerable = null;

    //Version
    private List<ProtocolVersion> versions = null;
    private Boolean supportsSsl2 = null;
    private Boolean supportsSsl3 = null;
    private Boolean supportsTls10 = null;
    private Boolean supportsTls11 = null;
    private Boolean supportsTls12 = null;
    private Boolean supportsTls13 = null;
    private Boolean supportsTls13Draft14 = null;
    private Boolean supportsTls13Draft15 = null;
    private Boolean supportsTls13Draft16 = null;
    private Boolean supportsTls13Draft17 = null;
    private Boolean supportsTls13Draft18 = null;
    private Boolean supportsTls13Draft19 = null;
    private Boolean supportsTls13Draft20 = null;
    private Boolean supportsTls13Draft21 = null;
    private Boolean supportsTls13Draft22 = null;
    private Boolean supportsTls13Draft23 = null;
    private Boolean supportsTls13Draft24 = null;
    private Boolean supportsTls13Draft25 = null;
    private Boolean supportsTls13Draft26 = null;
    private Boolean supportsTls13Draft27 = null;
    private Boolean supportsTls13Draft28 = null;
    private Boolean supportsDtls10 = null;
    private Boolean supportsDtls12 = null;
    private Boolean supportsDtls13 = null;

    //Extensions
    private List<ExtensionType> supportedExtensions = null;
    private List<NamedGroup> supportedNamedGroups = null;
    private List<NamedGroup> supportedTls13Groups = null;
    private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms = null;
    private List<TokenBindingVersion> supportedTokenBindingVersion = null;
    private List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters = null;
    private Boolean supportsExtendedMasterSecret = null;
    private Boolean supportsEncryptThenMacSecret = null;
    private Boolean supportsTokenbinding = null;

    //Compression
    private List<CompressionMethod> supportedCompressionMethods = null;

    //RFC
    private CheckPattern macCheckPatterAppData = null;
    private CheckPattern macCheckPatternFinished = null;
    private CheckPattern verifyCheckPattern = null;

    //Certificate
    private Certificate certificate = null;
    private List<CertificateReport> certificateReports = null;
    private Boolean certificateExpired = null;
    private Boolean certificateNotYetValid = null;
    private Boolean certificateHasWeakHashAlgorithm = null;
    private Boolean certificateHasWeakSignAlgorithm = null;
    private Boolean certificateMachtesDomainName = null;
    private Boolean certificateIsTrusted = null;
    private Boolean certificateKeyIsBlacklisted = null;

    //Ciphers
    private List<VersionSuiteListPair> versionSuitePairs = null;
    private Set<CipherSuite> cipherSuites = null;
    private List<CipherSuite> supportedTls13CipherSuites = null;
    private Boolean supportsNullCiphers = null;
    private Boolean supportsAnonCiphers = null;
    private Boolean supportsExportCiphers = null;
    private Boolean supportsDesCiphers = null;
    private Boolean supportsSeedCiphers = null;
    private Boolean supportsIdeaCiphers = null;
    private Boolean supportsRc2Ciphers = null;
    private Boolean supportsRc4Ciphers = null;
    private Boolean supportsTrippleDesCiphers = null;
    private Boolean supportsPostQuantumCiphers = null;
    private Boolean supportsAeadCiphers = null;
    private Boolean supportsPfsCiphers = null;
    private Boolean supportsOnlyPfsCiphers = null;
    private Boolean enforcesCipherSuiteOrdering = null;
    private Boolean supportsAes = null;
    private Boolean supportsCamellia = null;
    private Boolean supportsAria = null;
    private Boolean supportsChacha = null;
    private Boolean supportsRsa = null;
    private Boolean supportsDh = null;
    private Boolean supportsEcdh = null;
    private Boolean supportsStaticEcdh = null;
    private Boolean supportsGost = null;
    private Boolean supportsSrp = null;
    private Boolean supportsKerberos = null;
    private Boolean supportsPskPlain = null;
    private Boolean supportsPskRsa = null;
    private Boolean supportsPskDhe = null;
    private Boolean supportsPskEcdhe = null;
    private Boolean supportsFortezza = null;
    private Boolean supportsNewHope = null;
    private Boolean supportsEcmqv = null;
    private Boolean prefersPfsCiphers = null;
    private Boolean supportsStreamCiphers = null;
    private Boolean supportsBlockCiphers = null;

    //Session
    private Boolean supportsSessionTicket = null;
    private Boolean supportsSessionIds = null;
    private Long sessionTicketLengthHint = null;
    private Boolean sessionTicketGetsRotated = null;
    private Boolean vulnerableTicketBleed = null;

    //Renegotiation + SCSV
    private Boolean supportsSecureRenegotiation = null;
    private Boolean supportsClientSideSecureRenegotiation = null;
    private Boolean supportsClientSideInsecureRenegotiation = null;
    private Boolean tlsFallbackSCSVsupported = null;

    //GCM Nonces
    private Boolean gcmReuse = null;
    private GcmPattern gcmPattern = null;
    private Boolean gcmCheck = null;

    //HTTPS Header
    private Boolean speaksHttps;
    private List<HttpsHeader> headerList = null;
    private Boolean supportsHsts = null;
    private Integer hstsMaxAge = null;
    private Boolean supportsHstsPreloading = null;
    private Boolean supportsHpkp = null;
    private Boolean supportsHpkpReportOnly = null;
    private Integer hpkpMaxAge = null;
    private List<HpkpPin> normalHpkpPins;
    private List<HpkpPin> reportOnlyHpkpPins;
    //NoColor Flag
    private boolean noColor = false;

    //Handshake Simulation
    private Integer handshakeSuccessfulCounter = null;
    private Integer handshakeFailedCounter = null;
    private Integer connectionRfc7918SecureCounter = null;
    private Integer connectionInsecureCounter = null;
    private List<SimulatedClient> simulatedClientList = null;

    public SiteReport(String host, List<ProbeType> probeTypeList, boolean noColor) {
        this.host = host;
        this.probeTypeList = probeTypeList;
        this.noColor = noColor;
        performanceList = new LinkedList<>();
    }

    public String getHost() {
        return host;
    }

    public List<ProbeType> getProbeTypeList() {
        return probeTypeList;
    }

    public boolean isNoColor() {
        return noColor;
    }

    public Boolean getRequiresSni() {
        return requiresSni;
    }

    public void setRequiresSni(Boolean requiresSni) {
        this.requiresSni = requiresSni;
    }

    public Boolean getCompressionIntolerance() {
        return compressionIntolerance;
    }

    public void setCompressionIntolerance(Boolean compressionIntolerance) {
        this.compressionIntolerance = compressionIntolerance;
    }

    public Boolean getCipherSuiteLengthIntolerance512() {
        return cipherSuiteLengthIntolerance512;
    }

    public void setCipherSuiteLengthIntolerance512(Boolean cipherSuiteLengthIntolerance512) {
        this.cipherSuiteLengthIntolerance512 = cipherSuiteLengthIntolerance512;
    }

    public Boolean getAlpnIntolerance() {
        return alpnIntolerance;
    }

    public void setAlpnIntolerance(Boolean alpnIntolerance) {
        this.alpnIntolerance = alpnIntolerance;
    }

    public Boolean getClientHelloLengthIntolerance() {
        return clientHelloLengthIntolerance;
    }

    public void setClientHelloLengthIntolerance(Boolean clientHelloLengthIntolerance) {
        this.clientHelloLengthIntolerance = clientHelloLengthIntolerance;
    }

    public Boolean getEmptyLastExtensionIntolerance() {
        return emptyLastExtensionIntolerance;
    }

    public void setEmptyLastExtensionIntolerance(Boolean emptyLastExtensionIntolerance) {
        this.emptyLastExtensionIntolerance = emptyLastExtensionIntolerance;
    }

    public Boolean getOnlySecondCiphersuiteByteEvaluated() {
        return onlySecondCiphersuiteByteEvaluated;
    }

    public void setOnlySecondCiphersuiteByteEvaluated(Boolean onlySecondCiphersuiteByteEvaluated) {
        this.onlySecondCiphersuiteByteEvaluated = onlySecondCiphersuiteByteEvaluated;
    }

    public Boolean getNamedGroupIntolerant() {
        return namedGroupIntolerant;
    }

    public void setNamedGroupIntolerant(Boolean namedGroupIntolerant) {
        this.namedGroupIntolerant = namedGroupIntolerant;
    }

    public Boolean getNamedSignatureAndHashAlgorithmIntolerance() {
        return namedSignatureAndHashAlgorithmIntolerance;
    }

    public void setNamedSignatureAndHashAlgorithmIntolerance(Boolean namedSignatureAndHashAlgorithmIntolerance) {
        this.namedSignatureAndHashAlgorithmIntolerance = namedSignatureAndHashAlgorithmIntolerance;
    }

    public Boolean getIgnoresCipherSuiteOffering() {
        return ignoresCipherSuiteOffering;
    }

    public void setIgnoresCipherSuiteOffering(Boolean ignoresCipherSuiteOffering) {
        this.ignoresCipherSuiteOffering = ignoresCipherSuiteOffering;
    }

    public Boolean getReflectsCipherSuiteOffering() {
        return reflectsCipherSuiteOffering;
    }

    public void setReflectsCipherSuiteOffering(Boolean reflectsCipherSuiteOffering) {
        this.reflectsCipherSuiteOffering = reflectsCipherSuiteOffering;
    }

    public Boolean getIgnoresOfferedNamedGroups() {
        return ignoresOfferedNamedGroups;
    }

    public void setIgnoresOfferedNamedGroups(Boolean ignoresOfferedNamedGroups) {
        this.ignoresOfferedNamedGroups = ignoresOfferedNamedGroups;
    }

    public Boolean getIgnoresOfferedSignatureAndHashAlgorithms() {
        return ignoresOfferedSignatureAndHashAlgorithms;
    }

    public void setIgnoresOfferedSignatureAndHashAlgorithms(Boolean ignoresOfferedSignatureAndHashAlgorithms) {
        this.ignoresOfferedSignatureAndHashAlgorithms = ignoresOfferedSignatureAndHashAlgorithms;
    }

    public Boolean getMaxLengthClientHelloIntolerant() {
        return maxLengthClientHelloIntolerant;
    }

    public void setMaxLengthClientHelloIntolerant(Boolean maxLengthClientHelloIntolerant) {
        this.maxLengthClientHelloIntolerant = maxLengthClientHelloIntolerant;
    }

    public Boolean getFreakVulnerable() {
        return freakVulnerable;
    }

    public void setFreakVulnerable(Boolean freakVulnerable) {
        this.freakVulnerable = freakVulnerable;
    }

    public Boolean getHeartbleedVulnerable() {
        return heartbleedVulnerable;
    }

    public void setHeartbleedVulnerable(Boolean heartbleedVulnerable) {
        this.heartbleedVulnerable = heartbleedVulnerable;
    }

    public EarlyCcsVulnerabilityType getEarlyCcsVulnerable() {
        return earlyCcsVulnerable;
    }

    public void setEarlyCcsVulnerable(EarlyCcsVulnerabilityType earlyCcsVulnerable) {
        this.earlyCcsVulnerable = earlyCcsVulnerable;
    }

    public Boolean getServerIsAlive() {
        return serverIsAlive;
    }

    public void setServerIsAlive(Boolean serverIsAlive) {
        this.serverIsAlive = serverIsAlive;
    }

    public Boolean getSupportsSsl2() {
        return supportsSsl2;
    }

    public void setSupportsSsl2(Boolean supportsSsl2) {
        this.supportsSsl2 = supportsSsl2;
    }

    public Boolean getSupportsSsl3() {
        return supportsSsl3;
    }

    public void setSupportsSsl3(Boolean supportsSsl3) {
        this.supportsSsl3 = supportsSsl3;
    }

    public Boolean getSupportsTls10() {
        return supportsTls10;
    }

    public void setSupportsTls10(Boolean supportsTls10) {
        this.supportsTls10 = supportsTls10;
    }

    public Boolean getSupportsTls11() {
        return supportsTls11;
    }

    public void setSupportsTls11(Boolean supportsTls11) {
        this.supportsTls11 = supportsTls11;
    }

    public Boolean getSupportsTls12() {
        return supportsTls12;
    }

    public void setSupportsTls12(Boolean supportsTls12) {
        this.supportsTls12 = supportsTls12;
    }

    public Boolean supportsAnyTls13() {
        return supportsTls13 == Boolean.TRUE || supportsTls13Draft14 == Boolean.TRUE || supportsTls13Draft15 == Boolean.TRUE || supportsTls13Draft16 == Boolean.TRUE || supportsTls13Draft17 == Boolean.TRUE || supportsTls13Draft18 == Boolean.TRUE || supportsTls13Draft19 == Boolean.TRUE || supportsTls13Draft20 == Boolean.TRUE || supportsTls13Draft21 == Boolean.TRUE || supportsTls13Draft22 == Boolean.TRUE;
    }

    public Boolean getSupportsTls13() {
        return supportsTls13;
    }

    public void setSupportsTls13(Boolean supportsTls13) {
        this.supportsTls13 = supportsTls13;
    }

    public Boolean getSupportsTls13Draft14() {
        return supportsTls13Draft14;
    }

    public void setSupportsTls13Draft14(Boolean supportsTls13Draft14) {
        this.supportsTls13Draft14 = supportsTls13Draft14;
    }

    public Boolean getSupportsTls13Draft15() {
        return supportsTls13Draft15;
    }

    public void setSupportsTls13Draft15(Boolean supportsTls13Draft15) {
        this.supportsTls13Draft15 = supportsTls13Draft15;
    }

    public Boolean getSupportsTls13Draft16() {
        return supportsTls13Draft16;
    }

    public void setSupportsTls13Draft16(Boolean supportsTls13Draft16) {
        this.supportsTls13Draft16 = supportsTls13Draft16;
    }

    public Boolean getSupportsTls13Draft17() {
        return supportsTls13Draft17;
    }

    public void setSupportsTls13Draft17(Boolean supportsTls13Draft17) {
        this.supportsTls13Draft17 = supportsTls13Draft17;
    }

    public Boolean getSupportsTls13Draft18() {
        return supportsTls13Draft18;
    }

    public void setSupportsTls13Draft18(Boolean supportsTls13Draft18) {
        this.supportsTls13Draft18 = supportsTls13Draft18;
    }

    public Boolean getSupportsTls13Draft19() {
        return supportsTls13Draft19;
    }

    public void setSupportsTls13Draft19(Boolean supportsTls13Draft19) {
        this.supportsTls13Draft19 = supportsTls13Draft19;
    }

    public Boolean getSupportsTls13Draft20() {
        return supportsTls13Draft20;
    }

    public void setSupportsTls13Draft20(Boolean supportsTls13Draft20) {
        this.supportsTls13Draft20 = supportsTls13Draft20;
    }

    public Boolean getSupportsTls13Draft21() {
        return supportsTls13Draft21;
    }

    public void setSupportsTls13Draft21(Boolean supportsTls13Draft21) {
        this.supportsTls13Draft21 = supportsTls13Draft21;
    }

    public Boolean getSupportsTls13Draft22() {
        return supportsTls13Draft22;
    }

    public void setSupportsTls13Draft22(Boolean supportsTls13Draft22) {
        this.supportsTls13Draft22 = supportsTls13Draft22;
    }

    public Boolean getSupportsTls13Draft23() {
        return supportsTls13Draft23;
    }

    public void setSupportsTls13Draft23(Boolean supportsTls13Draft23) {
        this.supportsTls13Draft23 = supportsTls13Draft23;
    }

    public Boolean getSupportsTls13Draft24() {
        return supportsTls13Draft24;
    }

    public void setSupportsTls13Draft24(Boolean supportsTls13Draft24) {
        this.supportsTls13Draft24 = supportsTls13Draft24;
    }

    public Boolean getSupportsTls13Draft25() {
        return supportsTls13Draft25;
    }

    public void setSupportsTls13Draft25(Boolean supportsTls13Draft25) {
        this.supportsTls13Draft25 = supportsTls13Draft25;
    }

    public Boolean getSupportsTls13Draft26() {
        return supportsTls13Draft26;
    }

    public void setSupportsTls13Draft26(Boolean supportsTls13Draft26) {
        this.supportsTls13Draft26 = supportsTls13Draft26;
    }

    public Boolean getSupportsTls13Draft27() {
        return supportsTls13Draft27;
    }

    public void setSupportsTls13Draft27(Boolean supportsTls13Draft27) {
        this.supportsTls13Draft27 = supportsTls13Draft27;
    }

    public Boolean getSupportsTls13Draft28() {
        return supportsTls13Draft28;
    }

    public void setSupportsTls13Draft28(Boolean supportsTls13Draft28) {
        this.supportsTls13Draft28 = supportsTls13Draft28;
    }

    public Boolean getSupportsDtls10() {
        return supportsDtls10;
    }

    public void setSupportsDtls10(Boolean supportsDtls10) {
        this.supportsDtls10 = supportsDtls10;
    }

    public Boolean getSupportsDtls12() {
        return supportsDtls12;
    }

    public void setSupportsDtls12(Boolean supportsDtls12) {
        this.supportsDtls12 = supportsDtls12;
    }

    public Boolean getSupportsDtls13() {
        return supportsDtls13;
    }

    public void setSupportsDtls13(Boolean supportsDtls13) {
        this.supportsDtls13 = supportsDtls13;
    }

    public List<TokenBindingVersion> getSupportedTokenBindingVersion() {
        return supportedTokenBindingVersion;
    }

    public void setSupportedTokenBindingVersion(List<TokenBindingVersion> supportedTokenBindingVersion) {
        this.supportedTokenBindingVersion = supportedTokenBindingVersion;
    }

    public List<TokenBindingKeyParameters> getSupportedTokenBindingKeyParameters() {
        return supportedTokenBindingKeyParameters;
    }

    public void setSupportedTokenBindingKeyParameters(List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters) {
        this.supportedTokenBindingKeyParameters = supportedTokenBindingKeyParameters;
    }

    public List<CertificateReport> getCertificateReports() {
        return certificateReports;
    }

    public void setCertificateReports(List<CertificateReport> certificateReports) {
        this.certificateReports = certificateReports;
    }

    public Boolean getSupportsAes() {
        return supportsAes;
    }

    public void setSupportsAes(Boolean supportsAes) {
        this.supportsAes = supportsAes;
    }

    public Boolean getSupportsCamellia() {
        return supportsCamellia;
    }

    public void setSupportsCamellia(Boolean supportsCamellia) {
        this.supportsCamellia = supportsCamellia;
    }

    public Boolean getSupportsAria() {
        return supportsAria;
    }

    public void setSupportsAria(Boolean supportsAria) {
        this.supportsAria = supportsAria;
    }

    public Boolean getSupportsChacha() {
        return supportsChacha;
    }

    public void setSupportsChacha(Boolean supportsChacha) {
        this.supportsChacha = supportsChacha;
    }

    public Boolean getSupportsRsa() {
        return supportsRsa;
    }

    public void setSupportsRsa(Boolean supportsRsa) {
        this.supportsRsa = supportsRsa;
    }

    public Boolean getSupportsDh() {
        return supportsDh;
    }

    public void setSupportsDh(Boolean supportsDh) {
        this.supportsDh = supportsDh;
    }

    public Boolean getSupportsEcdh() {
        return supportsEcdh;
    }

    public void setSupportsEcdh(Boolean supportsEcdh) {
        this.supportsEcdh = supportsEcdh;
    }

    public Boolean getSupportsGost() {
        return supportsGost;
    }

    public void setSupportsGost(Boolean supportsGost) {
        this.supportsGost = supportsGost;
    }

    public Boolean getSupportsSrp() {
        return supportsSrp;
    }

    public void setSupportsSrp(Boolean supportsSrp) {
        this.supportsSrp = supportsSrp;
    }

    public Boolean getSupportsKerberos() {
        return supportsKerberos;
    }

    public void setSupportsKerberos(Boolean supportsKerberos) {
        this.supportsKerberos = supportsKerberos;
    }

    public Boolean getSupportsPskPlain() {
        return supportsPskPlain;
    }

    public void setSupportsPskPlain(Boolean supportsPskPlain) {
        this.supportsPskPlain = supportsPskPlain;
    }

    public Boolean getSupportsPskRsa() {
        return supportsPskRsa;
    }

    public void setSupportsPskRsa(Boolean supportsPskRsa) {
        this.supportsPskRsa = supportsPskRsa;
    }

    public Boolean getSupportsPskDhe() {
        return supportsPskDhe;
    }

    public void setSupportsPskDhe(Boolean supportsPskDhe) {
        this.supportsPskDhe = supportsPskDhe;
    }

    public Boolean getSupportsPskEcdhe() {
        return supportsPskEcdhe;
    }

    public void setSupportsPskEcdhe(Boolean supportsPskEcdhe) {
        this.supportsPskEcdhe = supportsPskEcdhe;
    }

    public Boolean getSupportsFortezza() {
        return supportsFortezza;
    }

    public void setSupportsFortezza(Boolean supportsFortezza) {
        this.supportsFortezza = supportsFortezza;
    }

    public Boolean getSupportsNewHope() {
        return supportsNewHope;
    }

    public void setSupportsNewHope(Boolean supportsNewHope) {
        this.supportsNewHope = supportsNewHope;
    }

    public Boolean getSupportsEcmqv() {
        return supportsEcmqv;
    }

    public void setSupportsEcmqv(Boolean supportsEcmqv) {
        this.supportsEcmqv = supportsEcmqv;
    }

    public Boolean getPrefersPfsCiphers() {
        return prefersPfsCiphers;
    }

    public void setPrefersPfsCiphers(Boolean prefersPfsCiphers) {
        this.prefersPfsCiphers = prefersPfsCiphers;
    }

    public Boolean getSupportsStreamCiphers() {
        return supportsStreamCiphers;
    }

    public void setSupportsStreamCiphers(Boolean supportsStreamCiphers) {
        this.supportsStreamCiphers = supportsStreamCiphers;
    }

    public Boolean getSupportsBlockCiphers() {
        return supportsBlockCiphers;
    }

    public void setSupportsBlockCiphers(Boolean supportsBlockCiphers) {
        this.supportsBlockCiphers = supportsBlockCiphers;
    }

    public Boolean getGcmCheck() {
        return gcmCheck;
    }

    public void setGcmCheck(Boolean gcmCheck) {
        this.gcmCheck = gcmCheck;
    }

    public List<ProtocolVersion> getVersions() {
        return versions;
    }

    public void setVersions(List<ProtocolVersion> versions) {
        this.versions = versions;
    }

    public Set<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(Set<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public List<CipherSuite> getSupportedTls13CipherSuites() {
        return supportedTls13CipherSuites;
    }

    public void setSupportedTls13CipherSuites(List<CipherSuite> supportedTls13CipherSuites) {
        this.supportedTls13CipherSuites = supportedTls13CipherSuites;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public Boolean getBleichenbacherVulnerable() {
        return bleichenbacherVulnerable;
    }

    public void setBleichenbacherVulnerable(Boolean bleichenbacherVulnerable) {
        this.bleichenbacherVulnerable = bleichenbacherVulnerable;
    }

    public Boolean getPaddingOracleVulnerable() {
        return paddingOracleVulnerable;
    }

    public void setPaddingOracleVulnerable(Boolean paddingOracleVulnerable) {
        this.paddingOracleVulnerable = paddingOracleVulnerable;
    }

    public Boolean getInvalidCurveVulnerable() {
        return invalidCurveVulnerable;
    }

    public void setInvalidCurveVulnerable(Boolean invalidCurveVulnerable) {
        this.invalidCurveVulnerable = invalidCurveVulnerable;
    }

    public Boolean getInvalidCurveEphermaralVulnerable() {
        return invalidCurveEphermaralVulnerable;
    }

    public void setInvalidCurveEphermaralVulnerable(Boolean invalidCurveEphermaralVulnerable) {
        this.invalidCurveEphermaralVulnerable = invalidCurveEphermaralVulnerable;
    }

    public Boolean getPoodleVulnerable() {
        return poodleVulnerable;
    }

    public void setPoodleVulnerable(Boolean poodleVulnerable) {
        this.poodleVulnerable = poodleVulnerable;
    }

    public Boolean getTlsPoodleVulnerable() {
        return tlsPoodleVulnerable;
    }

    public void setTlsPoodleVulnerable(Boolean tlsPoodleVulnerable) {
        this.tlsPoodleVulnerable = tlsPoodleVulnerable;
    }

    public Boolean getCve20162107Vulnerable() {
        return cve20162107Vulnerable;
    }

    public void setCve20162107Vulnerable(Boolean cve20162107Vulnerable) {
        this.cve20162107Vulnerable = cve20162107Vulnerable;
    }

    public Boolean getCrimeVulnerable() {
        return crimeVulnerable;
    }

    public void setCrimeVulnerable(Boolean crimeVulnerable) {
        this.crimeVulnerable = crimeVulnerable;
    }

    public Boolean getBreachVulnerable() {
        return breachVulnerable;
    }

    public void setBreachVulnerable(Boolean breachVulnerable) {
        this.breachVulnerable = breachVulnerable;
    }

    public Boolean getEnforcesCipherSuiteOrdering() {
        return enforcesCipherSuiteOrdering;
    }

    public void setEnforcesCipherSuiteOrdering(Boolean enforcesCipherSuiteOrdering) {
        this.enforcesCipherSuiteOrdering = enforcesCipherSuiteOrdering;
    }

    public List<NamedGroup> getSupportedNamedGroups() {
        return supportedNamedGroups;
    }

    public void setSupportedNamedGroups(List<NamedGroup> supportedNamedGroups) {
        this.supportedNamedGroups = supportedNamedGroups;
    }

    public List<NamedGroup> getSupportedTls13Groups() {
        return supportedTls13Groups;
    }

    public void setSupportedTls13Groups(List<NamedGroup> supportedTls13Groups) {
        this.supportedTls13Groups = supportedTls13Groups;
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
        return supportedSignatureAndHashAlgorithms;
    }

    public void setSupportedSignatureAndHashAlgorithms(List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
        this.supportedSignatureAndHashAlgorithms = supportedSignatureAndHashAlgorithms;
    }

    public List<ExtensionType> getSupportedExtensions() {
        return supportedExtensions;
    }

    public void setSupportedExtensions(List<ExtensionType> supportedExtensions) {
        this.supportedExtensions = supportedExtensions;
    }

    public List<CompressionMethod> getSupportedCompressionMethods() {
        return supportedCompressionMethods;
    }

    public void setSupportedCompressionMethods(List<CompressionMethod> supportedCompressionMethods) {
        this.supportedCompressionMethods = supportedCompressionMethods;
    }

    public CheckPattern getMacCheckPatternAppData() {
        return macCheckPatterAppData;
    }

    public void setMacCheckPatterAppData(CheckPattern macCheckPatterAppData) {
        this.macCheckPatterAppData = macCheckPatterAppData;
    }

    public CheckPattern getVerifyCheckPattern() {
        return verifyCheckPattern;
    }

    public void setVerifyCheckPattern(CheckPattern verifyCheckPattern) {
        this.verifyCheckPattern = verifyCheckPattern;
    }

    public Boolean getSupportsExtendedMasterSecret() {
        return supportsExtendedMasterSecret;
    }

    public void setSupportsExtendedMasterSecret(Boolean supportsExtendedMasterSecret) {
        this.supportsExtendedMasterSecret = supportsExtendedMasterSecret;
    }

    public Boolean getSupportsEncryptThenMacSecret() {
        return supportsEncryptThenMacSecret;
    }

    public void setSupportsEncryptThenMacSecret(Boolean supportsEncryptThenMacSecret) {
        this.supportsEncryptThenMacSecret = supportsEncryptThenMacSecret;
    }

    public Boolean getSupportsTokenbinding() {
        return supportsTokenbinding;
    }

    public void setSupportsTokenbinding(Boolean supportsTokenbinding) {
        this.supportsTokenbinding = supportsTokenbinding;
    }

    public Boolean getSupportsSslTls() {
        return supportsSslTls;
    }

    public void setSupportsSslTls(Boolean supportsSslTls) {
        this.supportsSslTls = supportsSslTls;
    }

    public Boolean getCertificateExpired() {
        return certificateExpired;
    }

    public void setCertificateExpired(Boolean certificateExpired) {
        this.certificateExpired = certificateExpired;
    }

    public Boolean getCertificateNotYetValid() {
        return certificateNotYetValid;
    }

    public void setCertificateNotYetValid(Boolean certificateNotYetValid) {
        this.certificateNotYetValid = certificateNotYetValid;
    }

    public Boolean getCertificateHasWeakHashAlgorithm() {
        return certificateHasWeakHashAlgorithm;
    }

    public void setCertificateHasWeakHashAlgorithm(Boolean certificateHasWeakHashAlgorithm) {
        this.certificateHasWeakHashAlgorithm = certificateHasWeakHashAlgorithm;
    }

    public Boolean getCertificateHasWeakSignAlgorithm() {
        return certificateHasWeakSignAlgorithm;
    }

    public void setCertificateHasWeakSignAlgorithm(Boolean certificateHasWeakSignAlgorithm) {
        this.certificateHasWeakSignAlgorithm = certificateHasWeakSignAlgorithm;
    }

    public Boolean getCertificateMachtesDomainName() {
        return certificateMachtesDomainName;
    }

    public void setCertificateMachtesDomainName(Boolean certificateMachtesDomainName) {
        this.certificateMachtesDomainName = certificateMachtesDomainName;
    }

    public Boolean getCertificateIsTrusted() {
        return certificateIsTrusted;
    }

    public void setCertificateIsTrusted(Boolean certificateIsTrusted) {
        this.certificateIsTrusted = certificateIsTrusted;
    }

    public Boolean getCertificateKeyIsBlacklisted() {
        return certificateKeyIsBlacklisted;
    }

    public void setCertificateKeyIsBlacklisted(Boolean certificateKeyIsBlacklisted) {
        this.certificateKeyIsBlacklisted = certificateKeyIsBlacklisted;
    }

    public Boolean getSupportsNullCiphers() {
        return supportsNullCiphers;
    }

    public void setSupportsNullCiphers(Boolean supportsNullCiphers) {
        this.supportsNullCiphers = supportsNullCiphers;
    }

    public Boolean getSupportsAnonCiphers() {
        return supportsAnonCiphers;
    }

    public void setSupportsAnonCiphers(Boolean supportsAnonCiphers) {
        this.supportsAnonCiphers = supportsAnonCiphers;
    }

    public Boolean getSupportsExportCiphers() {
        return supportsExportCiphers;
    }

    public void setSupportsExportCiphers(Boolean supportsExportCiphers) {
        this.supportsExportCiphers = supportsExportCiphers;
    }

    public Boolean getSupportsDesCiphers() {
        return supportsDesCiphers;
    }

    public void setSupportsDesCiphers(Boolean supportsDesCiphers) {
        this.supportsDesCiphers = supportsDesCiphers;
    }

    public Boolean getSupportsSeedCiphers() {
        return supportsSeedCiphers;
    }

    public void setSupportsSeedCiphers(Boolean supportsSeedCiphers) {
        this.supportsSeedCiphers = supportsSeedCiphers;
    }

    public Boolean getSupportsIdeaCiphers() {
        return supportsIdeaCiphers;
    }

    public void setSupportsIdeaCiphers(Boolean supportsIdeaCiphers) {
        this.supportsIdeaCiphers = supportsIdeaCiphers;
    }

    public Boolean getSupportsRc2Ciphers() {
        return supportsRc2Ciphers;
    }

    public void setSupportsRc2Ciphers(Boolean supportsRc2Ciphers) {
        this.supportsRc2Ciphers = supportsRc2Ciphers;
    }

    public Boolean getSupportsRc4Ciphers() {
        return supportsRc4Ciphers;
    }

    public void setSupportsRc4Ciphers(Boolean supportsRc4Ciphers) {
        this.supportsRc4Ciphers = supportsRc4Ciphers;
    }

    public Boolean getSupportsTrippleDesCiphers() {
        return supportsTrippleDesCiphers;
    }

    public void setSupportsTrippleDesCiphers(Boolean supportsTrippleDesCiphers) {
        this.supportsTrippleDesCiphers = supportsTrippleDesCiphers;
    }

    public Boolean getSupportsPostQuantumCiphers() {
        return supportsPostQuantumCiphers;
    }

    public void setSupportsPostQuantumCiphers(Boolean supportsPostQuantumCiphers) {
        this.supportsPostQuantumCiphers = supportsPostQuantumCiphers;
    }

    public Boolean getSupportsAeadCiphers() {
        return supportsAeadCiphers;
    }

    public void setSupportsAeadCiphers(Boolean supportsAeadCiphers) {
        this.supportsAeadCiphers = supportsAeadCiphers;
    }

    public Boolean getSupportsPfsCiphers() {
        return supportsPfsCiphers;
    }

    public void setSupportsPfsCiphers(Boolean supportsPfsCiphers) {
        this.supportsPfsCiphers = supportsPfsCiphers;
    }

    public Boolean getSupportsOnlyPfsCiphers() {
        return supportsOnlyPfsCiphers;
    }

    public void setSupportsOnlyPfsCiphers(Boolean supportsOnlyPfsCiphers) {
        this.supportsOnlyPfsCiphers = supportsOnlyPfsCiphers;
    }

    public Boolean getSupportsSessionTicket() {
        return supportsSessionTicket;
    }

    public void setSupportsSessionTicket(Boolean supportsSessionTicket) {
        this.supportsSessionTicket = supportsSessionTicket;
    }

    public Boolean getSupportsSessionIds() {
        return supportsSessionIds;
    }

    public void setSupportsSessionIds(Boolean supportsSessionIds) {
        this.supportsSessionIds = supportsSessionIds;
    }

    public Long getSessionTicketLengthHint() {
        return sessionTicketLengthHint;
    }

    public void setSessionTicketLengthHint(Long sessionTicketLengthHint) {
        this.sessionTicketLengthHint = sessionTicketLengthHint;
    }

    public Boolean getSessionTicketGetsRotated() {
        return sessionTicketGetsRotated;
    }

    public void setSessionTicketGetsRotated(Boolean sessionTicketGetsRotated) {
        this.sessionTicketGetsRotated = sessionTicketGetsRotated;
    }

    public Boolean getVulnerableTicketBleed() {
        return vulnerableTicketBleed;
    }

    public void setVulnerableTicketBleed(Boolean vulnerableTicketBleed) {
        this.vulnerableTicketBleed = vulnerableTicketBleed;
    }

    public Boolean getSupportsSecureRenegotiation() {
        return supportsSecureRenegotiation;
    }

    public void setSupportsSecureRenegotiation(Boolean supportsSecureRenegotiation) {
        this.supportsSecureRenegotiation = supportsSecureRenegotiation;
    }

    public Boolean getSupportsClientSideSecureRenegotiation() {
        return supportsClientSideSecureRenegotiation;
    }

    public void setSupportsClientSideSecureRenegotiation(Boolean supportsClientSideSecureRenegotiation) {
        this.supportsClientSideSecureRenegotiation = supportsClientSideSecureRenegotiation;
    }

    public Boolean getSupportsClientSideInsecureRenegotiation() {
        return supportsClientSideInsecureRenegotiation;
    }

    public void setSupportsClientSideInsecureRenegotiation(Boolean supportsClientSideInsecureRenegotiation) {
        this.supportsClientSideInsecureRenegotiation = supportsClientSideInsecureRenegotiation;
    }

    public Boolean getTlsFallbackSCSVsupported() {
        return tlsFallbackSCSVsupported;
    }

    public void setTlsFallbackSCSVsupported(Boolean tlsFallbackSCSVsupported) {
        this.tlsFallbackSCSVsupported = tlsFallbackSCSVsupported;
    }

    public Boolean getSweet32Vulnerable() {
        return sweet32Vulnerable;
    }

    public void setSweet32Vulnerable(Boolean sweet32Vulnerable) {
        this.sweet32Vulnerable = sweet32Vulnerable;
    }

    public DrownVulnerabilityType getDrownVulnerable() {
        return drownVulnerable;
    }

    public void setDrownVulnerable(DrownVulnerabilityType drownVulnerable) {
        this.drownVulnerable = drownVulnerable;
    }

    public Boolean getLogjamVulnerable() {
        return logjamVulnerable;
    }

    public void setLogjamVulnerable(Boolean logjamVulnerable) {
        this.logjamVulnerable = logjamVulnerable;
    }

    public Boolean getVersionIntolerance() {
        return versionIntolerance;
    }

    public void setVersionIntolerance(Boolean versionIntolerance) {
        this.versionIntolerance = versionIntolerance;
    }

    public Boolean getExtensionIntolerance() {
        return extensionIntolerance;
    }

    public void setExtensionIntolerance(Boolean extensionIntolerance) {
        this.extensionIntolerance = extensionIntolerance;
    }

    public Boolean getCipherSuiteIntolerance() {
        return cipherSuiteIntolerance;
    }

    public void setCipherSuiteIntolerance(Boolean cipherSuiteIntolerance) {
        this.cipherSuiteIntolerance = cipherSuiteIntolerance;
    }

    public Boolean getGcmReuse() {
        return gcmReuse;
    }

    public void setGcmReuse(Boolean gcmReuse) {
        this.gcmReuse = gcmReuse;
    }

    public GcmPattern getGcmPattern() {
        return gcmPattern;
    }

    public void setGcmPattern(GcmPattern gcmPattern) {
        this.gcmPattern = gcmPattern;
    }

    public List<VersionSuiteListPair> getVersionSuitePairs() {
        return versionSuitePairs;
    }

    public void setVersionSuitePairs(List<VersionSuiteListPair> versionSuitePairs) {
        this.versionSuitePairs = versionSuitePairs;
    }

    public Boolean getSupportsStaticEcdh() {
        return supportsStaticEcdh;
    }

    public void setSupportsStaticEcdh(Boolean supportsStaticEcdh) {
        this.supportsStaticEcdh = supportsStaticEcdh;
    }

    public Integer getHandshakeSuccessfulCounter() {
        return handshakeSuccessfulCounter;
    }

    public void setHandshakeSuccessfulCounter(Integer handshakeSuccessfulCounter) {
        this.handshakeSuccessfulCounter = handshakeSuccessfulCounter;
    }

    public Integer getHandshakeFailedCounter() {
        return handshakeFailedCounter;
    }

    public void setHandshakeFailedCounter(Integer handshakeFailedCounter) {
        this.handshakeFailedCounter = handshakeFailedCounter;
    }

    public Integer getConnectionRfc7918SecureCounter() {
        return connectionRfc7918SecureCounter;
    }

    public void setConnectionRfc7918SecureCounter(Integer connectionRfc7918SecureCounter) {
        this.connectionRfc7918SecureCounter = connectionRfc7918SecureCounter;
    }

    public Integer getConnectionInsecureCounter() {
        return connectionInsecureCounter;
    }

    public void setConnectionInsecureCounter(Integer connectionInsecureCounter) {
        this.connectionInsecureCounter = connectionInsecureCounter;
    }

    public List<SimulatedClient> getSimulatedClientList() {
        return simulatedClientList;
    }

    public void setSimulatedClientList(List<SimulatedClient> simulatedClientList) {
        this.simulatedClientList = simulatedClientList;
    }

    public String getFullReport(ScannerDetail detail) {
        return new SiteReportPrinter(this, detail).getFullReport();
    }

    @Override
    public String toString() {
        return getFullReport(ScannerDetail.NORMAL);
    }

    public CheckPattern getMacCheckPatternFinished() {
        return macCheckPatternFinished;
    }

    public void setMacCheckPatternFinished(CheckPattern macCheckPatternFinished) {
        this.macCheckPatternFinished = macCheckPatternFinished;
    }

    public List<PerformanceData> getPerformanceList() {
        return performanceList;
    }

    public void setPerformanceList(List<PerformanceData> performanceList) {
        this.performanceList = performanceList;
    }

    public List<PaddingOracleTestResult> getPaddingOracleTestResultList() {
        return paddingOracleTestResultList;
    }

    public void setPaddingOracleTestResultList(List<PaddingOracleTestResult> paddingOracleTestResultList) {
        this.paddingOracleTestResultList = paddingOracleTestResultList;
    }

    public List<HttpsHeader> getHeaderList() {
        return headerList;
    }

    public void setHeaderList(List<HttpsHeader> headerList) {
        this.headerList = headerList;
    }

    public Boolean getSupportsHsts() {
        return supportsHsts;
    }

    public void setSupportsHsts(Boolean supportsHsts) {
        this.supportsHsts = supportsHsts;
    }

    public Boolean getSupportsHstsPreloading() {
        return supportsHstsPreloading;
    }

    public void setSupportsHstsPreloading(Boolean supportsHstsPreloading) {
        this.supportsHstsPreloading = supportsHstsPreloading;
    }

    public Boolean getSupportsHpkp() {
        return supportsHpkp;
    }

    public void setSupportsHpkp(Boolean supportsHpkp) {
        this.supportsHpkp = supportsHpkp;
    }

    public Boolean getSpeaksHttps() {
        return speaksHttps;
    }

    public void setSpeaksHttps(Boolean speaksHttps) {
        this.speaksHttps = speaksHttps;
    }

    public Integer getHstsMaxAge() {
        return hstsMaxAge;
    }

    public void setHstsMaxAge(Integer hstsMaxAge) {
        this.hstsMaxAge = hstsMaxAge;
    }

    public Integer getHpkpMaxAge() {
        return hpkpMaxAge;
    }

    public void setHpkpMaxAge(Integer hpkpMaxAge) {
        this.hpkpMaxAge = hpkpMaxAge;
    }

    public List<HpkpPin> getNormalHpkpPins() {
        return normalHpkpPins;
    }

    public void setNormalHpkpPins(List<HpkpPin> normalHpkpPins) {
        this.normalHpkpPins = normalHpkpPins;
    }

    public List<HpkpPin> getReportOnlyHpkpPins() {
        return reportOnlyHpkpPins;
    }

    public void setReportOnlyHpkpPins(List<HpkpPin> reportOnlyHpkpPins) {
        this.reportOnlyHpkpPins = reportOnlyHpkpPins;
    }

    public Boolean getSupportsHpkpReportOnly() {
        return supportsHpkpReportOnly;
    }

    public void setSupportsHpkpReportOnly(Boolean supportsHpkpReportOnly) {
        this.supportsHpkpReportOnly = supportsHpkpReportOnly;
    }
}
