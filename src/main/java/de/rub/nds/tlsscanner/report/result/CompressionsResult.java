/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CompressionsResult extends ProbeResult {

    private List<CompressionMethod> compressions;

    public CompressionsResult(List<CompressionMethod> compressions) {
        super(ProbeType.COMPRESSIONS);
        this.compressions = compressions;
    }

    @Override
    public void merge(SiteReport report) {
        report.setSupportedCompressionMethods(compressions);
        if (compressions.size() > 1) {
            report.setCrimeVulnerable(Boolean.TRUE);
        } else {
            report.setCrimeVulnerable(Boolean.FALSE);
        }
    }

}
