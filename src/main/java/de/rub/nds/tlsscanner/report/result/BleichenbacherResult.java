/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.bleichenbacher.BleichenbacherTestResult;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class BleichenbacherResult extends ProbeResult {

    private Boolean vulnerable;
    private List<BleichenbacherTestResult> resultList;

    public BleichenbacherResult(Boolean vulnerable, List<BleichenbacherTestResult> resultList) {
        super(ProbeType.BLEICHENBACHER);
        this.vulnerable = vulnerable;
        this.resultList = resultList;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setBleichenbacherVulnerable(vulnerable);
        report.setBleichenbacherTestResultList(resultList);
    }

}
