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

    public PaddingOracleResult(List<PaddingOracleTestResult> resultList) {
        super(ProbeType.PADDING_ORACLE);
        this.resultList = resultList;
    }

    @Override
    public void mergeData(SiteReport report) {
        Boolean vulnerable = null;
        if (resultList.isEmpty()) {
            vulnerable = false;
        }
        for (PaddingOracleTestResult result : resultList) {
            if (result.getVulnerable() == Boolean.TRUE) {
                vulnerable = true;
            } else if (result.getVulnerable() == Boolean.FALSE && vulnerable == null) {
                vulnerable = false;
            }
        }
        report.setPaddingOracleTestResultList(resultList);
        report.setPaddingOracleVulnerable(vulnerable);
    }
}
