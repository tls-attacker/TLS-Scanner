/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.GeneralDrownAttacker;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.SpecialDrownAttacker;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.constans.DrownOracleType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.DrownResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DrownProbe extends TlsProbe {

    public DrownProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.DROWN, configSelector);
    }

    @Override
    public ProbeResult executeTest() {
        return new DrownResult(testForGeneralDrown(), testForExtraClearDrown());
    }

    private TestResult testForGeneralDrown() {
        GeneralDrownAttacker attacker =
            new GeneralDrownAttacker(getConfigSelector().getSSL2BaseConfig(), getParallelExecutor());
        return attacker.isVulnerable();
    }

    private TestResult testForExtraClearDrown() {
        SpecialDrownAttacker attacker = new SpecialDrownAttacker(getConfigSelector().getSSL2BaseConfig(),
            getParallelExecutor(), DrownOracleType.EXTRA_CLEAR);
        return attacker.isVulnerable();
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.isProbeAlreadyExecuted(ProbeType.PROTOCOL_VERSION)
            && report.getResult(AnalyzedProperty.SUPPORTS_SSL_2) == TestResult.TRUE;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new DrownResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }
}
