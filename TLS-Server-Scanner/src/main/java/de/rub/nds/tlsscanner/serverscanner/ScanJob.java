/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner;

import de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.report.after.AfterProbe;
import java.util.List;

/**
 *
 * @author Robert Merget - {@literal <robert.merget@rub.de>}
 */
public class ScanJob {

    private final List<TlsProbe> probeList;
    private final List<AfterProbe> afterList;

    public ScanJob(List<TlsProbe> probeList, List<AfterProbe> afterList) {
        this.probeList = probeList;
        this.afterList = afterList;
    }

    public List<TlsProbe> getProbeList() {
        return probeList;
    }

    public List<AfterProbe> getAfterList() {
        return afterList;
    }
}
