/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.TLSPoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.TLSPoodleAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.TlsPoodleResult;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsPoodleProbe extends TlsProbe {

    public TlsPoodleProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.TLS_POODLE, config);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            TLSPoodleCommandConfig poodleCommandConfig = new TLSPoodleCommandConfig(getScannerConfig()
                    .getGeneralDelegate());
            ClientDelegate delegate = (ClientDelegate) poodleCommandConfig.getDelegate(ClientDelegate.class);
            delegate.setHost(getScannerConfig().getClientDelegate().getHost());
            delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
            if (getScannerConfig().getDtlsDelegate().isDTLS()) {
                ProtocolVersionDelegate protocolVersionDelegate = (ProtocolVersionDelegate) poodleCommandConfig
                        .getDelegate(ProtocolVersionDelegate.class);
                protocolVersionDelegate.setProtocolVersion(ProtocolVersion.DTLS12);
            }
            StarttlsDelegate starttlsDelegate = (StarttlsDelegate) poodleCommandConfig
                    .getDelegate(StarttlsDelegate.class);
            starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
            TLSPoodleAttacker attacker = new TLSPoodleAttacker(poodleCommandConfig, poodleCommandConfig.createConfig());
            Boolean vulnerable = attacker.isVulnerable();
            return new TlsPoodleResult(vulnerable == true ? TestResult.TRUE : TestResult.FALSE);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new TlsPoodleResult(TestResult.ERROR_DURING_TEST);
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
        return new TlsPoodleResult(TestResult.COULD_NOT_TEST);
    }
}
