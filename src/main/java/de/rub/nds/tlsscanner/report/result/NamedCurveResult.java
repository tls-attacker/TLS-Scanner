/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class NamedCurveResult extends ProbeResult {
    
    private final List<NamedCurve> namedCurvesList;
    
    public NamedCurveResult(List<NamedCurve> curves) {
        super(ProbeType.NAMED_CURVES);
        this.namedCurvesList = curves;
    }
    
    @Override
    public void merge(SiteReport report) {
        report.setSupportedNamedCurves(namedCurvesList);
    }
    
}
