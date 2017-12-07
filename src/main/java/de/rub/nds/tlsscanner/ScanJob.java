/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.report.AfterProbe;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ScanJob {

    private final List<TlsProbe> probeList;

    public ScanJob(List<TlsProbe> testList) {
        this.probeList = testList;
    }

    public List<TlsProbe> getProbeList() {
        return probeList;
    }

    public List<AfterProbe> getAfterProbes() {
        return new LinkedList<>();
    }
}
