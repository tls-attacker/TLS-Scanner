/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author robert
 */
public class CommonBugProbeResult extends ProbeResult {

    private final TestResult extensionIntolerance; // does it handle unknown
    // extenstions correctly?
    private final TestResult cipherSuiteIntolerance; // does it handle unknown
    // ciphersuites correctly?
    private final TestResult cipherSuiteLengthIntolerance512; // does it handle
    // long
    // ciphersuite
    // length values
    // correctly?

    private final TestResult compressionIntolerance; // does it handle unknown
    // compression algorithms
    // correctly
    private final TestResult versionIntolerance; // does it handle unknown
    // versions correctly?
    private final TestResult alpnIntolerance; // does it handle unknown alpn
    // strings correctly?
    private final TestResult clientHelloLengthIntolerance; // 256 - 511 <-- ch
    // should be bigger
    // than this
    private final TestResult emptyLastExtensionIntolerance; // does it break on
    // empty last
    // extension
    private final TestResult onlySecondCiphersuiteByteEvaluated; // is only the
    // second byte
    // of the
    // ciphersuite
    // evaluated
    private final TestResult namedGroupIntolerant; // does it handle unknown
    // groups correctly
    private final TestResult namedSignatureAndHashAlgorithmIntolerance; // does
    // it
    // handle
    // signature
    // and
    // hash
    // algorithms
    // correctly
    private final TestResult ignoresCipherSuiteOffering; // does it ignore the
    // offered ciphersuites
    private final TestResult reflectsCipherSuiteOffering; // does it ignore the
    // offered
    // ciphersuites
    private final TestResult ignoresOfferedNamedGroups; // does it ignore the
    // offered named groups
    private final TestResult ignoresOfferedSignatureAndHashAlgorithms; // does
    // it
    // ignore
    // the
    // sig
    // hash
    // algorithms
    private final TestResult maxLengthClientHelloIntolerant; // server does not

    // like really big
    // client hello
    // messages
    public CommonBugProbeResult(TestResult extensionIntolerance, TestResult cipherSuiteIntolerance,
            TestResult cipherSuiteLengthIntolerance512, TestResult compressionIntolerance,
            TestResult versionIntolerance, TestResult alpnIntolerance, TestResult clientHelloLengthIntolerance,
            TestResult emptyLastExtensionIntolerance, TestResult onlySecondCiphersuiteByteEvaluated,
            TestResult namedGroupIntolerant, TestResult namedSignatureAndHashAlgorithmIntolerance,
            TestResult ignoresCipherSuiteOffering, TestResult reflectsCipherSuiteOffering,
            TestResult ignoresOfferedNamedGroups, TestResult ignoresOfferedSignatureAndHashAlgorithms,
            TestResult maxLengthClientHelloIntolerant) {
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
        report.putResult(AnalyzedProperty.HAS_EXTENSION_INTOLERANCE, extensionIntolerance);
        report.putResult(AnalyzedProperty.HAS_CIPHERSUITE_INTOLERANCE, cipherSuiteIntolerance);
        report.putResult(AnalyzedProperty.HAS_CIPHERSUITE_LENGTH_INTOLERANCE, cipherSuiteLengthIntolerance512);
        report.putResult(AnalyzedProperty.HAS_COMPRESSION_INTOLERANCE, compressionIntolerance);
        report.putResult(AnalyzedProperty.HAS_VERSION_INTOLERANCE, versionIntolerance);
        report.putResult(AnalyzedProperty.HAS_ALPN_INTOLERANCE, alpnIntolerance);
        report.putResult(AnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE, clientHelloLengthIntolerance);
        report.putResult(AnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE, emptyLastExtensionIntolerance);
        report.putResult(AnalyzedProperty.HAS_SECOND_CIPHERSUITE_BYTE_BUG, onlySecondCiphersuiteByteEvaluated);
        report.putResult(AnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE, namedGroupIntolerant);
        report.putResult(AnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE, namedSignatureAndHashAlgorithmIntolerance);
        report.putResult(AnalyzedProperty.IGNORES_OFFERED_CIPHERSUITES, ignoresCipherSuiteOffering);
        report.putResult(AnalyzedProperty.REFLECTS_OFFERED_CIPHERSUITES, reflectsCipherSuiteOffering);
        report.putResult(AnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS, ignoresOfferedNamedGroups);
        report.putResult(AnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS, ignoresOfferedSignatureAndHashAlgorithms);
        report.putResult(AnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE, maxLengthClientHelloIntolerant);
    }

}
