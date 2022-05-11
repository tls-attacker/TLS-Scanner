/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.GeneralDrownAttacker;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.SpecialDrownAttacker;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.constans.DrownOracleType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.DrownResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DrownProbe extends TlsServerProbe<ConfigSelector, ServerReport, DrownResult> {

    public DrownProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DROWN, configSelector);
    }

    @Override
    public DrownResult executeTest() {
        return new DrownResult(testForGeneralDrown(), testForExtraClearDrown());
    }

    private TestResults testForGeneralDrown() {
        GeneralDrownAttacker attacker =
            new GeneralDrownAttacker(configSelector.getSSL2BaseConfig(), getParallelExecutor());
        return attacker.isVulnerable();
    }

    private TestResults testForExtraClearDrown() {
        SpecialDrownAttacker attacker = new SpecialDrownAttacker(configSelector.getSSL2BaseConfig(),
            getParallelExecutor(), DrownOracleType.EXTRA_CLEAR);
        return attacker.isVulnerable();
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return report.isProbeAlreadyExecuted(TlsProbeType.PROTOCOL_VERSION)
            && report.getResult(TlsAnalyzedProperty.SUPPORTS_SSL_2) == TestResults.TRUE;
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    public DrownResult getCouldNotExecuteResult() {
        return new DrownResult(TestResults.COULD_NOT_TEST, TestResults.COULD_NOT_TEST);
    }
}
