/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.execution;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import java.util.LinkedList;
import java.util.List;

public abstract class TlsScanner {
    protected final List<ScannerProbe> probeList;
    protected final List<AfterProbe> afterList;
    protected final List<ProbeType> probesToExecute;

    public TlsScanner(List<ProbeType> probesToExecute) {
        this(new LinkedList<>(), new LinkedList<>(), probesToExecute);
    }

    public TlsScanner(List<ScannerProbe> probeList, List<AfterProbe> afterList, List<ProbeType> probesToExecute) {
        this.probesToExecute = probesToExecute;
        this.afterList = afterList;
        this.probeList = probeList;
    }

    protected abstract void fillDefaultProbeLists();

    protected void addProbeToProbeList(TlsProbe probe) {
        if (probesToExecute == null || probesToExecute.contains(probe.getType())) {
            probeList.add(probe);
        }
    }
}
