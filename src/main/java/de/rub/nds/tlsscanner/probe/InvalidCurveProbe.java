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
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.InvalidCurveResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class InvalidCurveProbe extends TlsProbe {

    private TestResult supportsEphemeral;

    private TestResult supportsStatic;

    public InvalidCurveProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.INVALID_CURVE, config, 10);
    }

    @Override
    public ProbeResult executeTest() {
        TestResult vulnerableClassic = TestResult.NOT_TESTED_YET;
        TestResult vulnerableEphemeral = TestResult.NOT_TESTED_YET;
        if (supportsStatic == TestResult.TRUE) {
            try {
                InvalidCurveAttackConfig invalidCurveAttackConfig = new InvalidCurveAttackConfig(getScannerConfig()
                        .getGeneralDelegate());
                ClientDelegate delegate = (ClientDelegate) invalidCurveAttackConfig.getDelegate(ClientDelegate.class);
                delegate.setHost(getScannerConfig().getClientDelegate().getHost());
                delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
                StarttlsDelegate starttlsDelegate = (StarttlsDelegate) invalidCurveAttackConfig
                        .getDelegate(StarttlsDelegate.class);
                starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
                InvalidCurveAttacker attacker = new InvalidCurveAttacker(invalidCurveAttackConfig,
                        invalidCurveAttackConfig.createConfig());
                Boolean vuln = attacker.isVulnerable();
                if (vuln == null) {
                    vulnerableClassic = TestResult.COULD_NOT_TEST;
                } else if (vuln == Boolean.TRUE) {
                    vulnerableClassic = TestResult.TRUE;
                } else if (vuln == Boolean.FALSE) {
                    vulnerableClassic = TestResult.FALSE;
                }
            } catch (Exception E) {
                LOGGER.error("Could not scan for StaticInvalidCurve. Error during probe execution", E);
                vulnerableClassic = TestResult.ERROR_DURING_TEST;
            }
        } else {
            vulnerableClassic = TestResult.COULD_NOT_TEST;
        }
        if (supportsEphemeral == TestResult.TRUE) {
            try {
                InvalidCurveAttackConfig invalidCurveAttackConfig = new InvalidCurveAttackConfig(getScannerConfig()
                        .getGeneralDelegate());
                invalidCurveAttackConfig.setEphemeral(true);
                StarttlsDelegate starttlsDelegate = (StarttlsDelegate) invalidCurveAttackConfig
                        .getDelegate(StarttlsDelegate.class);
                starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
                ClientDelegate delegate = (ClientDelegate) invalidCurveAttackConfig.getDelegate(ClientDelegate.class);
                delegate.setHost(getScannerConfig().getClientDelegate().getHost());
                delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
                InvalidCurveAttacker attacker = new InvalidCurveAttacker(invalidCurveAttackConfig,
                        invalidCurveAttackConfig.createConfig());
                Boolean vuln = attacker.isVulnerable();
                if (vuln == null) {
                    vulnerableEphemeral = TestResult.COULD_NOT_TEST;
                } else if (vuln == Boolean.TRUE) {
                    vulnerableEphemeral = TestResult.TRUE;
                } else if (vuln == Boolean.FALSE) {
                    vulnerableEphemeral = TestResult.FALSE;
                }
            } catch (Exception E) {
                LOGGER.error("Could not scan for EphemeralInvalidCurve. Error during probe execution", E);
                vulnerableEphemeral = TestResult.ERROR_DURING_TEST;
            }
        } else {
            vulnerableEphemeral = TestResult.COULD_NOT_TEST;
        }
        return new InvalidCurveResult(vulnerableClassic, vulnerableEphemeral);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_ECDH) == TestResult.TRUE
                || report.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) == TestResult.TRUE;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportsEphemeral = report.getResult(AnalyzedProperty.SUPPORTS_ECDH);
        supportsStatic = report.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new InvalidCurveResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }

}
