/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleTestResult;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class PaddingOracleResult extends ProbeResult {

    private List<PaddingOracleTestResult> resultList;

    private Boolean vulnerable;

    public PaddingOracleResult(List<PaddingOracleTestResult> resultList, Boolean vulnerable) {
        super(ProbeType.PADDING_ORACLE);
        this.resultList = resultList;
        this.vulnerable = vulnerable;
    }

    @Override
    public void mergeData(SiteReport report) {
        if (resultList.isEmpty() && vulnerable == null) {
            vulnerable = false;
        }

        report.setPaddingOracleTestResultList(resultList);
        report.setPaddingOracleVulnerable(vulnerable);
    }
}
