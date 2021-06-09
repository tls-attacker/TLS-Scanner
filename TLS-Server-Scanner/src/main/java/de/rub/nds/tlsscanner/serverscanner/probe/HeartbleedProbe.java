/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.HeartbleedAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.CipherSuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.HeartbleedResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 *
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public class HeartbleedProbe extends TlsProbe {

    private List<CipherSuite> supportedCiphers;

    public HeartbleedProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.HEARTBLEED, config);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            HeartbleedCommandConfig heartbleedConfig =
                new HeartbleedCommandConfig(getScannerConfig().getGeneralDelegate());
            ClientDelegate delegate = (ClientDelegate) heartbleedConfig.getDelegate(ClientDelegate.class);
            delegate.setHost(getScannerConfig().getClientDelegate().getHost());
            delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
            StarttlsDelegate starttlsDelegate = (StarttlsDelegate) heartbleedConfig.getDelegate(StarttlsDelegate.class);
            starttlsDelegate.setStarttlsType(getScannerConfig().getStarttlsDelegate().getStarttlsType());
            if (supportedCiphers != null) {
                CipherSuiteDelegate cipherSuiteDelegate =
                    (CipherSuiteDelegate) heartbleedConfig.getDelegate(CipherSuiteDelegate.class);
                cipherSuiteDelegate.setCipherSuites(supportedCiphers);
            }
            HeartbleedAttacker attacker = new HeartbleedAttacker(heartbleedConfig, heartbleedConfig.createConfig());
            Boolean vulnerable = attacker.isVulnerable();
            return new HeartbleedResult(Objects.equals(vulnerable, Boolean.TRUE) ? TestResult.TRUE : TestResult.FALSE);
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new HeartbleedResult(TestResult.ERROR_DURING_TEST);
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (report.getSupportedExtensions() != null) {
            for (ExtensionType type : report.getSupportedExtensions()) {
                if (type == ExtensionType.HEARTBEAT) {
                    return true;
                }
            }
        } else {
            return true;
        }
        return false;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        if (report.getCipherSuites() != null && !report.getCipherSuites().isEmpty()) {
            supportedCiphers = new ArrayList<>(report.getCipherSuites());
        } else {
            supportedCiphers = CipherSuite.getImplemented();
        }
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new HeartbleedResult(TestResult.COULD_NOT_TEST);
    }
}
