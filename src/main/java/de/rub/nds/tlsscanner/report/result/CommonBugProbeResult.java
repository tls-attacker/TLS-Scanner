package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author robert
 */
public class CommonBugProbeResult extends ProbeResult {
    
    private final Boolean extensionIntolerance; //does it handle unknown extenstions correctly?
    private final Boolean cipherSuiteIntolerance; //does it handle unknown ciphersuites correctly?
    private final Boolean cipherSuiteLengthIntolerance512; //does it handle long ciphersuite length values correctly?

    private final Boolean compressionIntolerance; //does it handle unknown compression algorithms correctly
    private final Boolean versionIntolerance; //does it handle unknown versions correctly?
    private final Boolean alpnIntolerance; //does it handle unknown alpn strings correctly?
    private final Boolean clientHelloLengthIntolerance; // 256 - 511 <-- ch should be bigger than this
    private final Boolean emptyLastExtensionIntolerance; //does it break on empty last extension
    private final Boolean onlySecondCiphersuiteByteEvaluated; //is only the second byte of the ciphersuite evaluated
    private final Boolean namedGroupIntolerant; // does it handle unknown groups correctly
    private final Boolean namedSignatureAndHashAlgorithmIntolerance; // does it handle signature and hash algorithms correctly
    private final Boolean ignoresCipherSuiteOffering; //does it ignore the offered ciphersuites
    private final Boolean reflectsCipherSuiteOffering; //does it ignore the offered ciphersuites
    private final Boolean ignoresOfferedNamedGroups; //does it ignore the offered named groups
    private final Boolean ignoresOfferedSignatureAndHashAlgorithms; //does it ignore the sig hash algorithms
    private final Boolean maxLengthClientHelloIntolerant; // server does not like really big client hello messages

    public CommonBugProbeResult(Boolean extensionIntolerance, Boolean cipherSuiteIntolerance, Boolean cipherSuiteLengthIntolerance512, Boolean compressionIntolerance, Boolean versionIntolerance, Boolean alpnIntolerance, Boolean clientHelloLengthIntolerance, Boolean emptyLastExtensionIntolerance, Boolean onlySecondCiphersuiteByteEvaluated, Boolean namedGroupIntolerant, Boolean namedSignatureAndHashAlgorithmIntolerance, Boolean ignoresCipherSuiteOffering, Boolean reflectsCipherSuiteOffering, Boolean ignoresOfferedNamedGroups, Boolean ignoresOfferedSignatureAndHashAlgorithms, Boolean maxLengthClientHelloIntolerant) {
        super(ProbeType.COMMON_BUGS);
        this.extensionIntolerance = extensionIntolerance;
        this.cipherSuiteIntolerance = cipherSuiteIntolerance;
        this.cipherSuiteLengthIntolerance512 = cipherSuiteLengthIntolerance512;
        this.compressionIntolerance = compressionIntolerance;
        this.versionIntolerance = versionIntolerance;
        this.alpnIntolerance = alpnIntolerance;
        this.clientHelloLengthIntolerance = clientHelloLengthIntolerance;
        this.emptyLastExtensionIntolerance = emptyLastExtensionIntolerance;
        this.onlySecondCiphersuiteByteEvaluated = onlySecondCiphersuiteByteEvaluated;
        this.namedGroupIntolerant = namedGroupIntolerant;
        this.namedSignatureAndHashAlgorithmIntolerance = namedSignatureAndHashAlgorithmIntolerance;
        this.ignoresCipherSuiteOffering = ignoresCipherSuiteOffering;
        this.reflectsCipherSuiteOffering = reflectsCipherSuiteOffering;
        this.ignoresOfferedNamedGroups = ignoresOfferedNamedGroups;
        this.ignoresOfferedSignatureAndHashAlgorithms = ignoresOfferedSignatureAndHashAlgorithms;
        this.maxLengthClientHelloIntolerant = maxLengthClientHelloIntolerant;
    }
    
    @Override
    protected void mergeData(SiteReport report) {
        report.setExtensionIntolerance(extensionIntolerance);
        report.setCipherSuiteIntolerance(cipherSuiteIntolerance);
        report.setCipherSuiteLengthIntolerance512(cipherSuiteLengthIntolerance512);
        report.setCompressionIntolerance(compressionIntolerance);
        report.setVersionIntolerance(versionIntolerance);
        report.setAlpnIntolerance(alpnIntolerance);
        report.setClientHelloLengthIntolerance(clientHelloLengthIntolerance);
        report.setEmptyLastExtensionIntolerance(emptyLastExtensionIntolerance);
        report.setOnlySecondCiphersuiteByteEvaluated(onlySecondCiphersuiteByteEvaluated);
        report.setNamedGroupIntolerant(namedGroupIntolerant);
        report.setNamedSignatureAndHashAlgorithmIntolerance(namedSignatureAndHashAlgorithmIntolerance);
        report.setIgnoresCipherSuiteOffering(ignoresCipherSuiteOffering);
        report.setReflectsCipherSuiteOffering(reflectsCipherSuiteOffering);
        report.setIgnoresOfferedNamedGroups(ignoresOfferedNamedGroups);
        report.setIgnoresOfferedSignatureAndHashAlgorithms(ignoresOfferedSignatureAndHashAlgorithms);
        report.setMaxLengthClientHelloIntolerant(maxLengthClientHelloIntolerant);
    }
    
}
