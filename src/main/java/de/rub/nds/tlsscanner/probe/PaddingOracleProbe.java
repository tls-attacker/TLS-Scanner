/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.result.PaddingOracleResult;
import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class PaddingOracleProbe extends TlsProbe {

    public PaddingOracleProbe(ScannerConfig config) {
        super(ProbeType.PADDING_ORACLE, config, 9);
    }

    @Override
    public ProbeResult executeTest() {
        PaddingOracleCommandConfig paddingOracleConfig = new PaddingOracleCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) paddingOracleConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        PaddingOracleAttacker attacker = new PaddingOracleAttacker(paddingOracleConfig, paddingOracleConfig.createConfig());
        Boolean vulnerable = attacker.isVulnerable();
        return new PaddingOracleResult(vulnerable);
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
        return new PaddingOracleResult(Boolean.FALSE);
    }
}
