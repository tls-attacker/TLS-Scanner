/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.core.probe.requirements.PropertyRequirement;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.GeneralDrownAttacker;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.SpecialDrownAttacker;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.constans.DrownOracleType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DrownProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private TestResult generalDrown;
    private TestResult extraClear;

    public DrownProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DROWN, configSelector);
        register(TlsAnalyzedProperty.VULNERABLE_TO_EXTRA_CLEAR_DROWN, TlsAnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN);
    }

    @Override
    public void executeTest() {
        generalDrown = testForGeneralDrown();
        extraClear = testForExtraClearDrown();
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
    public void adjustConfig(ServerReport report) {
    }

    @Override
    protected Requirement getRequirements() {
        return new ProbeRequirement(TlsProbeType.PROTOCOL_VERSION)
            .requires(new PropertyRequirement(TlsAnalyzedProperty.SUPPORTS_SSL_2));
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.VULNERABLE_TO_EXTRA_CLEAR_DROWN, extraClear);
        put(TlsAnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN, generalDrown);
    }
}
