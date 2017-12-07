/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CertificateResult extends ProbeResult {

    private List<CertificateReport> reportList;

    public CertificateResult(ProbeType type, List<CertificateReport> reportList) {
        super(type);
        this.reportList = reportList;
    }

    @Override
    public void merge(SiteReport report) {
        report.setCertificateReports(reportList);
    }

}
