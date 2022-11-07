/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.execution;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import java.util.List;

public class ScanJob {

    private final List<ScannerProbe> probeList;
    private final List<AfterProbe> afterList;

    public ScanJob(List<ScannerProbe> probeList, List<AfterProbe> afterList) {
        this.probeList = probeList;
        this.afterList = afterList;
    }

    public List<ScannerProbe> getProbeList() {
        return probeList;
    }

    public List<AfterProbe> getAfterList() {
        return afterList;
    }
}
