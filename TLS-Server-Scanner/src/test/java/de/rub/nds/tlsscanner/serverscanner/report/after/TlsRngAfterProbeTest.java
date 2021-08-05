/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.after;

import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.junit.Before;

public class TlsRngAfterProbeTest {

    private SiteReport testReport;
    private RandomnessAfterProbe randomnessTester;

    public TlsRngAfterProbeTest() {
    }

    @Before
    public void setUp() {
        randomnessTester = new RandomnessAfterProbe();
        testReport = new SiteReport("test");
    }
}
