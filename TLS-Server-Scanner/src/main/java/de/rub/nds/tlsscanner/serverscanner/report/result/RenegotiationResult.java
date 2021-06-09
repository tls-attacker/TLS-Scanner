/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author robert
 */
public class RenegotiationResult extends ProbeResult {

    private final TestResult secureRenegotiationExtension;
    private final TestResult secureRenegotiationCipherSuite;
    private final TestResult insecureRenegotiation;
    private final TestResult vulnerableRenegotiationAttack;
    private final TestResult vulnerableRenegotiationAttackCipherSuite;

    public RenegotiationResult(TestResult secureRenegotiationExtension, TestResult secureRenegotiationCipherSuite,
        TestResult insecureRenegotiation, TestResult vulnerableRenegotiationAttack,
        TestResult vulnerableRenegotiationAttackCipherSuite) {
        super(ProbeType.RENEGOTIATION);
        this.secureRenegotiationExtension = secureRenegotiationExtension;
        this.secureRenegotiationCipherSuite = secureRenegotiationCipherSuite;
        this.insecureRenegotiation = insecureRenegotiation;
        this.vulnerableRenegotiationAttack = vulnerableRenegotiationAttack;
        this.vulnerableRenegotiationAttackCipherSuite = vulnerableRenegotiationAttackCipherSuite;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION,
            secureRenegotiationExtension);
        report.putResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_CIPHERSUITE,
            secureRenegotiationCipherSuite);
        report.putResult(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION, insecureRenegotiation);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION, vulnerableRenegotiationAttack);
        report.putResult(AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE,
            vulnerableRenegotiationAttackCipherSuite);
    }

}
