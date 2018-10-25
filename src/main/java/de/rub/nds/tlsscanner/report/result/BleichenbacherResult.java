/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
