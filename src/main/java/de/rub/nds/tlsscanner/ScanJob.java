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
import de.rub.nds.tlsscanner.report.after.AfterProbe;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ScanJob {

    private final List<TlsProbe> phaseTwoTestList;
    private final List<TlsProbe> phaseOneTestList;
    private final List<AfterProbe> afterList;

    public ScanJob(List<TlsProbe> phaseOneTestList, List<TlsProbe> phaseTwoTestList, List<AfterProbe> afterList) {
        this.phaseOneTestList = phaseOneTestList;
        this.phaseTwoTestList = phaseTwoTestList;
        this.afterList = afterList;
    }

    public List<TlsProbe> getPhaseOneTestList() {
        return phaseOneTestList;
    }

    public List<TlsProbe> getPhaseTwoTestList() {
        return phaseTwoTestList;
    }

    public List<AfterProbe> getAfterList() {
        return afterList;
    }
}
