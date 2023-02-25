/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class CommonBugProbeResult extends ProbeResult<ServerReport> {

    // does it handle unknown extensions correctly?
    private final TestResult extensionIntolerance;
    // does it handle unknown cipher suites correctly?
    private final TestResult cipherSuiteIntolerance;
    // does it handle long cipher suite length values correctly?
    private final TestResult cipherSuiteLengthIntolerance512;
    // does it handle unknown compression algorithms correctly?
    private final TestResult compressionIntolerance;
    // does it handle unknown versions correctly?
    private final TestResult versionIntolerance;
    // does it handle unknown alpn strings correctly?
    private final TestResult alpnIntolerance;
    // 256 - 511 <-- ch should be bigger than this?
    private final TestResult clientHelloLengthIntolerance;
    // does it break on empty last extension?
    private final TestResult emptyLastExtensionIntolerance;
    // is only the second byte of the cipher suite evaluated?
    private final TestResult onlySecondCipherSuiteByteEvaluated;
    // does it handle unknown groups correctly?
    private final TestResult namedGroupIntolerant;
    // does it handle signature and hash algorithms correctly?
    private final TestResult namedSignatureAndHashAlgorithmIntolerance;
    // does it ignore the offered cipher suites?
    private final TestResult ignoresCipherSuiteOffering;
    // does it ignore the offered cipher suites?
    private final TestResult reflectsCipherSuiteOffering;
    // does it ignore the offered named groups?
    private final TestResult ignoresOfferedNamedGroups;
    // does it ignore the sig hash algorithms?
    private final TestResult ignoresOfferedSignatureAndHashAlgorithms;
    // server does not like really big client hello messages?
    private final TestResult maxLengthClientHelloIntolerant;
    // does it accept grease values in the supported groups extension?
    private TestResult greaseNamedGroupIntolerance;
    // does it accept grease values in the cipher suites list?
    private TestResult greaseCipherSuiteIntolerance;
    // does it accept grease values in the signature and hash algorithms extension?
    private TestResult greaseSignatureAndHashAlgorithmIntolerance;

    public CommonBugProbeResult(
            TestResult extensionIntolerance,
            TestResult cipherSuiteIntolerance,
            TestResult cipherSuiteLengthIntolerance512,
            TestResult compressionIntolerance,
            TestResult versionIntolerance,
            TestResult alpnIntolerance,
            TestResult clientHelloLengthIntolerance,
            TestResult emptyLastExtensionIntolerance,
            TestResult onlySecondCipherSuiteByteEvaluated,
            TestResult namedGroupIntolerant,
            TestResult namedSignatureAndHashAlgorithmIntolerance,
            TestResult ignoresCipherSuiteOffering,
            TestResult reflectsCipherSuiteOffering,
            TestResult ignoresOfferedNamedGroups,
            TestResult ignoresOfferedSignatureAndHashAlgorithms,
            TestResult maxLengthClientHelloIntolerant,
            TestResult greaseNamedGroupIntolerance,
            TestResult greaseCipherSuiteIntolerance,
            TestResult greaseSignatureAndHashAlgorithmIntolerance) {
        super(TlsProbeType.COMMON_BUGS);
        this.extensionIntolerance = extensionIntolerance;
        this.cipherSuiteIntolerance = cipherSuiteIntolerance;
        this.cipherSuiteLengthIntolerance512 = cipherSuiteLengthIntolerance512;
        this.compressionIntolerance = compressionIntolerance;
        this.versionIntolerance = versionIntolerance;
        this.alpnIntolerance = alpnIntolerance;
        this.clientHelloLengthIntolerance = clientHelloLengthIntolerance;
        this.emptyLastExtensionIntolerance = emptyLastExtensionIntolerance;
        this.onlySecondCipherSuiteByteEvaluated = onlySecondCipherSuiteByteEvaluated;
        this.namedGroupIntolerant = namedGroupIntolerant;
        this.namedSignatureAndHashAlgorithmIntolerance = namedSignatureAndHashAlgorithmIntolerance;
        this.ignoresCipherSuiteOffering = ignoresCipherSuiteOffering;
        this.reflectsCipherSuiteOffering = reflectsCipherSuiteOffering;
        this.ignoresOfferedNamedGroups = ignoresOfferedNamedGroups;
        this.ignoresOfferedSignatureAndHashAlgorithms = ignoresOfferedSignatureAndHashAlgorithms;
        this.maxLengthClientHelloIntolerant = maxLengthClientHelloIntolerant;
        this.greaseNamedGroupIntolerance = greaseNamedGroupIntolerance;
        this.greaseCipherSuiteIntolerance = greaseCipherSuiteIntolerance;
        this.greaseSignatureAndHashAlgorithmIntolerance =
                greaseSignatureAndHashAlgorithmIntolerance;
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.putResult(TlsAnalyzedProperty.HAS_EXTENSION_INTOLERANCE, extensionIntolerance);
        report.putResult(TlsAnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE, cipherSuiteIntolerance);
        report.putResult(
                TlsAnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE,
                cipherSuiteLengthIntolerance512);
        report.putResult(TlsAnalyzedProperty.HAS_COMPRESSION_INTOLERANCE, compressionIntolerance);
        report.putResult(TlsAnalyzedProperty.HAS_VERSION_INTOLERANCE, versionIntolerance);
        report.putResult(TlsAnalyzedProperty.HAS_ALPN_INTOLERANCE, alpnIntolerance);
        report.putResult(
                TlsAnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE,
                clientHelloLengthIntolerance);
        report.putResult(
                TlsAnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE,
                emptyLastExtensionIntolerance);
        report.putResult(
                TlsAnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG,
                onlySecondCipherSuiteByteEvaluated);
        report.putResult(TlsAnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE, namedGroupIntolerant);
        report.putResult(
                TlsAnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE,
                namedSignatureAndHashAlgorithmIntolerance);
        report.putResult(
                TlsAnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES, ignoresCipherSuiteOffering);
        report.putResult(
                TlsAnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES, reflectsCipherSuiteOffering);
        report.putResult(
                TlsAnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS, ignoresOfferedNamedGroups);
        report.putResult(
                TlsAnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS,
                ignoresOfferedSignatureAndHashAlgorithms);
        report.putResult(
                TlsAnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE,
                maxLengthClientHelloIntolerant);
        report.putResult(
                TlsAnalyzedProperty.HAS_GREASE_NAMED_GROUP_INTOLERANCE,
                greaseNamedGroupIntolerance);
        report.putResult(
                TlsAnalyzedProperty.HAS_GREASE_CIPHER_SUITE_INTOLERANCE,
                greaseCipherSuiteIntolerance);
        report.putResult(
                TlsAnalyzedProperty.HAS_GREASE_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE,
                greaseSignatureAndHashAlgorithmIntolerance);
    }
}
