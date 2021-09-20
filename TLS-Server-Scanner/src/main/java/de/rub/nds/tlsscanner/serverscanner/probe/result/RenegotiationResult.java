/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author robert
 */
public class RenegotiationResult extends ProbeResult<SiteReport> {

    private final TestResult secureRenegotiationExtension;
    private final TestResult secureRenegotiationCipherSuite;
    private final TestResult insecureRenegotiation;
    private final TestResult vulnerableRenegotiationAttackExtensionV1;
    private final TestResult vulnerableRenegotiationAttackExtensionV2;
    private final TestResult vulnerableRenegotiationAttackCipherSuiteV1;
    private final TestResult vulnerableRenegotiationAttackCipherSuiteV2;
    private final TestResult supportsDtlsCookieExchangeInRenegotiation;

    public RenegotiationResult(TestResult secureRenegotiationExtension, TestResult secureRenegotiationCipherSuite,
        TestResult insecureRenegotiation, TestResult vulnerableRenegotiationAttackExtensionV1,
        TestResult vulnerableRenegotiationAttackExtensionV2, TestResult vulnerableRenegotiationAttackCipherSuiteV1,
        TestResult vulnerableRenegotiationAttackCipherSuiteV2, TestResult supportsDtlsCookieExchangeInRenegotiation) {
        super(ProbeType.RENEGOTIATION);
        this.secureRenegotiationExtension = secureRenegotiationExtension;
        this.secureRenegotiationCipherSuite = secureRenegotiationCipherSuite;
        this.insecureRenegotiation = insecureRenegotiation;
        this.vulnerableRenegotiationAttackExtensionV1 = vulnerableRenegotiationAttackExtensionV1;
        this.vulnerableRenegotiationAttackExtensionV2 = vulnerableRenegotiationAttackExtensionV2;
        this.vulnerableRenegotiationAttackCipherSuiteV1 = vulnerableRenegotiationAttackCipherSuiteV1;
        this.vulnerableRenegotiationAttackCipherSuiteV2 = vulnerableRenegotiationAttackCipherSuiteV2;
        this.supportsDtlsCookieExchangeInRenegotiation = supportsDtlsCookieExchangeInRenegotiation;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION,
            secureRenegotiationExtension);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_CIPHERSUITE,
            secureRenegotiationCipherSuite);
        report.putResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION, insecureRenegotiation);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V1,
            vulnerableRenegotiationAttackExtensionV1);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V2,
            vulnerableRenegotiationAttackExtensionV2);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V1,
            vulnerableRenegotiationAttackCipherSuiteV1);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V2,
            vulnerableRenegotiationAttackCipherSuiteV2);
        report.putResult(AnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_RENEGOTIATION,
            supportsDtlsCookieExchangeInRenegotiation);
    }

}
