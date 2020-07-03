/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.GeneralDrownCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.SpecialDrownCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.drown.GeneralDrownAttacker;
import de.rub.nds.tlsattacker.attacks.impl.drown.SpecialDrownAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.DrownResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import java.util.Objects;

public class DrownProbe extends TlsProbe {

    public DrownProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.DROWN, scannerConfig, 8);
    }

    @Override
    public ProbeResult executeTest() {
        return new DrownResult(testForGeneralDrown(), testForExtraClearDrown());
    }

    private TestResult testForGeneralDrown() {
        try {
            GeneralDrownCommandConfig drownCommandConfig = new GeneralDrownCommandConfig(getScannerConfig()
                    .getGeneralDelegate());
            ClientDelegate delegate = (ClientDelegate) drownCommandConfig.getDelegate(ClientDelegate.class);
            delegate.setHost(getScannerConfig().getClientDelegate().getHost());
            delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
            StarttlsDelegate starttlsDelegate = (StarttlsDelegate) drownCommandConfig
                    .getDelegate(StarttlsDelegate.class);
            starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
            GeneralDrownAttacker attacker = new GeneralDrownAttacker(drownCommandConfig,
                    drownCommandConfig.createConfig());
            Boolean generalDrown = attacker.isVulnerable();
            if (Objects.equals(generalDrown, Boolean.TRUE)) {
                return TestResult.TRUE;
            } else {
                return TestResult.FALSE;
            }
        } catch (Exception E) {
            LOGGER.error("Could not scan for testForGeneralDrown():" + getProbeName(), E);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    private TestResult testForExtraClearDrown() {
        try {
            SpecialDrownCommandConfig drownCommandConfig = new SpecialDrownCommandConfig(getScannerConfig()
                    .getGeneralDelegate());

            ClientDelegate delegate = (ClientDelegate) drownCommandConfig.getDelegate(ClientDelegate.class);
            delegate.setHost(getScannerConfig().getClientDelegate().getHost());
            delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
            StarttlsDelegate starttlsDelegate = (StarttlsDelegate) drownCommandConfig
                    .getDelegate(StarttlsDelegate.class);
            starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
            SpecialDrownAttacker attacker = new SpecialDrownAttacker(drownCommandConfig,
                    drownCommandConfig.createConfig());
            Boolean generalDrown = attacker.isVulnerable();
            if (Objects.equals(generalDrown, Boolean.TRUE)) {
                return TestResult.TRUE;
            } else {
                return TestResult.FALSE;
            }
        } catch (Exception E) {
            LOGGER.error("Could not scan for testForExtraClearDrown():" + getProbeName(), E);
            return TestResult.ERROR_DURING_TEST;
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new DrownResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }
}
