/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.probe.result;

import de.rub.nds.tlsscanner.clientscanner.probe.result.dhe.CompositeModulusResult;
import de.rub.nds.tlsscanner.clientscanner.probe.result.dhe.SmallSubgroupResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.List;

public class DheParameterResult extends ProbeResult<ClientReport> {

    private final List<SmallSubgroupResult> smallSubgroupResults;
    private final List<CompositeModulusResult> compositeModulusResultList;
    private final Integer lowestDheModulusLength;

    public DheParameterResult(Integer lowestDheModulusLength, List<SmallSubgroupResult> smallSubgroupResults,
        List<CompositeModulusResult> compositeModulusResultList) {
        super(TlsProbeType.DH_PARAMETERS);
        this.smallSubgroupResults = smallSubgroupResults;
        this.compositeModulusResultList = compositeModulusResultList;
        this.lowestDheModulusLength = lowestDheModulusLength;
    }

    @Override
    protected void mergeData(ClientReport report) {
        report.setCompositeDheModulusResultList(compositeModulusResultList);
        report.setSmallDheSubgroupResults(smallSubgroupResults);
        report.setLowestPossibleDheModulusSize(lowestDheModulusLength);
    }

}
