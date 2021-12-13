/*
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsattacker.attacks.config.TLSPoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.TLSPoodleAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.TlsPoodleResult;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsPoodleProbe extends TlsProbe {

    public TlsPoodleProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.TLS_POODLE, config, 8);
    }

    @Override
    public ProbeResult executeTest() {
        TLSPoodleCommandConfig poodleCommandConfig = new TLSPoodleCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) poodleCommandConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        StarttlsDelegate starttlsDelegate = (StarttlsDelegate) poodleCommandConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
        TLSPoodleAttacker attacker = new TLSPoodleAttacker(poodleCommandConfig, poodleCommandConfig.createConfig());
        Boolean vulnerable = attacker.isVulnerable();
        return new TlsPoodleResult(vulnerable);
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return report.getSupportsBlockCiphers();
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new TlsPoodleResult(Boolean.FALSE);
    }
}
