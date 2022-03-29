/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsattacker.attacks.config.GeneralDrownCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.SpecialDrownCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.drown.GeneralDrownAttacker;
import de.rub.nds.tlsattacker.attacks.impl.drown.SpecialDrownAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.probe.result.DrownResult;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import java.util.Objects;

public class DrownProbe extends TlsProbe<ServerScannerConfig, ServerReport, DrownResult> {

    public DrownProbe(ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DROWN, scannerConfig);
    }

    @Override
    public DrownResult executeTest() {
        return new DrownResult(testForGeneralDrown(), testForExtraClearDrown());
    }

    private TestResult testForGeneralDrown() {
        GeneralDrownCommandConfig drownCommandConfig =
            new GeneralDrownCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) drownCommandConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        StarttlsDelegate starttlsDelegate = (StarttlsDelegate) drownCommandConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
        GeneralDrownAttacker attacker = new GeneralDrownAttacker(drownCommandConfig, drownCommandConfig.createConfig());
        Boolean generalDrown = attacker.isVulnerable();
        if (Objects.equals(generalDrown, Boolean.TRUE)) {
            return TestResult.TRUE;
        } else {
            return TestResult.FALSE;
        }
    }

    private TestResult testForExtraClearDrown() {
        try {
            SpecialDrownCommandConfig drownCommandConfig =
                new SpecialDrownCommandConfig(getScannerConfig().getGeneralDelegate());

            ClientDelegate delegate = (ClientDelegate) drownCommandConfig.getDelegate(ClientDelegate.class);
            delegate.setHost(((ServerScannerConfig) scannerConfig).getClientDelegate().getHost());
            delegate.setSniHostname(((ServerScannerConfig) scannerConfig).getClientDelegate().getSniHostname());
            StarttlsDelegate starttlsDelegate =
                (StarttlsDelegate) drownCommandConfig.getDelegate(StarttlsDelegate.class);
            starttlsDelegate
                .setStarttlsType(((ServerScannerConfig) scannerConfig).getStarttlsDelegate().getStarttlsType());
            SpecialDrownAttacker attacker =
                new SpecialDrownAttacker(drownCommandConfig, drownCommandConfig.createConfig());
            Boolean generalDrown = attacker.isVulnerable();
            if (Objects.equals(generalDrown, Boolean.TRUE)) {
                return TestResult.TRUE;
            } else {
                return TestResult.FALSE;
            }
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not scan for testForExtraClearDrown():" + getProbeName(), e);
            }
            return TestResult.ERROR_DURING_TEST;
        }
    }

    @Override
    public boolean canBeExecuted(ServerReport report) {
        return true;
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    public DrownResult getCouldNotExecuteResult() {
        return new DrownResult(TestResult.COULD_NOT_TEST, TestResult.COULD_NOT_TEST);
    }
}
