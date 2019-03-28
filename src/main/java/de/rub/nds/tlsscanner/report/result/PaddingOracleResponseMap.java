/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleCipherSuiteFingerprint;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class PaddingOracleResponseMap extends ProbeResult {

    private final List<PaddingOracleCipherSuiteFingerprint> resultList;
    private final List<PaddingOracleCipherSuiteFingerprint> shakyEvalList;

    private Boolean vulnerable;

    public PaddingOracleResponseMap(List<PaddingOracleCipherSuiteFingerprint> resultList, List<PaddingOracleCipherSuiteFingerprint> shakyEvalList, Boolean vulnerable) {
        super(ProbeType.PADDING_ORACLE);
        this.resultList = resultList;
        this.shakyEvalList = shakyEvalList;
        this.vulnerable = vulnerable;
    }

    @Override
    public void mergeData(SiteReport report) {
        if (resultList.isEmpty() && vulnerable == null) {
            vulnerable = false;
        }

        report.setPaddingOracleTestResultList(resultList);
        report.setPaddingOracleShakyEvalResultList(shakyEvalList);
        report.setPaddingOracleVulnerable(vulnerable);
    }

    public List<PaddingOracleCipherSuiteFingerprint> getResultList() {
        return resultList;
    }

}
