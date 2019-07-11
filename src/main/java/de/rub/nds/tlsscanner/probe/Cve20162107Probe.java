/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsattacker.attacks.config.Cve20162107CommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.Cve20162107Attacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.Cve20162107Result;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class Cve20162107Probe extends TlsProbe {

    public Cve20162107Probe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.CVE20162107, config, 10);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            // introduce try catch block as this one into every executeTest
            // change boolean result to TestResult
            Cve20162107CommandConfig cve20162106config = new Cve20162107CommandConfig(getScannerConfig().getGeneralDelegate());
            ClientDelegate delegate = (ClientDelegate) cve20162106config.getDelegate(ClientDelegate.class);
            StarttlsDelegate starttlsDelegate = (StarttlsDelegate) cve20162106config.getDelegate(StarttlsDelegate.class);
            starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
            delegate.setHost(getScannerConfig().getClientDelegate().getHost());
            Cve20162107Attacker attacker = new Cve20162107Attacker(cve20162106config, cve20162106config.createConfig());
            Boolean vulnerable = attacker.isVulnerable();
            return new Cve20162107Result(vulnerable);
        } catch(Exception e) {
            return new Cve20162107Result(TestResult.ERROR_DURING_TEST);
        }
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return report.getSupportsBlockCiphers() == Boolean.TRUE;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new Cve20162107Result(Boolean.FALSE);
    }
}
