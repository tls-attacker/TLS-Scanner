/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.PropertyTrueRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProtocolTypeFalseRequirement;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.GeneralDrownAttacker;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.SpecialDrownAttacker;
import de.rub.nds.tlsscanner.serverscanner.probe.drown.constans.DrownOracleType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DrownProbe extends TlsServerProbe {

    private TestResult generalDrown = TestResults.COULD_NOT_TEST;
    private TestResult extraClear = TestResults.COULD_NOT_TEST;

    public DrownProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DROWN, configSelector);
        register(
                TlsAnalyzedProperty.VULNERABLE_TO_EXTRA_CLEAR_DROWN,
                TlsAnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN);
    }

    @Override
    protected void executeTest() {
        generalDrown = testForGeneralDrown();
        extraClear = testForExtraClearDrown();
    }

    private TestResults testForGeneralDrown() {
        GeneralDrownAttacker attacker =
                new GeneralDrownAttacker(configSelector.getSSL2BaseConfig(), getParallelExecutor());
        return attacker.isVulnerable();
    }

    private TestResults testForExtraClearDrown() {
        SpecialDrownAttacker attacker =
                new SpecialDrownAttacker(
                        configSelector.getSSL2BaseConfig(),
                        getParallelExecutor(),
                        DrownOracleType.EXTRA_CLEAR);
        return attacker.isVulnerable();
    }

    @Override
    public void adjustConfig(ServerReport report) {}

    @Override
    public Requirement<ServerReport> getRequirements() {
        return new ProtocolTypeFalseRequirement<ServerReport>(ProtocolType.DTLS)
                .and(new ProbeRequirement<>(TlsProbeType.PROTOCOL_VERSION))
                .and(new PropertyTrueRequirement<>(TlsAnalyzedProperty.SUPPORTS_SSL_2));
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.VULNERABLE_TO_EXTRA_CLEAR_DROWN, extraClear);
        put(TlsAnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN, generalDrown);
    }
}
