/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.HeartbleedAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.HeartbleedResult;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HeartbleedProbe extends TlsProbe {

    private List<CipherSuite> supportedCiphers;

    public HeartbleedProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.HEARTBLEED, config, 9);
    }

    @Override
    public ProbeResult executeTest() {
        HeartbleedCommandConfig heartbleedConfig = new HeartbleedCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) heartbleedConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        StarttlsDelegate starttlsDelegate = (StarttlsDelegate) heartbleedConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(getScannerConfig().getStarttlsDelegate().getStarttlsType());
        if (supportedCiphers != null) {
            CiphersuiteDelegate ciphersuiteDelegate = (CiphersuiteDelegate) heartbleedConfig.getDelegate(CiphersuiteDelegate.class);
            ciphersuiteDelegate.setCipherSuites(supportedCiphers);
        }
        HeartbleedAttacker attacker = new HeartbleedAttacker(heartbleedConfig, heartbleedConfig.createConfig());
        Boolean vulnerable = attacker.isVulnerable();
        return new HeartbleedResult(vulnerable);
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
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
    public ProbeResult getNotExecutedResult() {
        return new HeartbleedResult(Boolean.FALSE);
    }
}
