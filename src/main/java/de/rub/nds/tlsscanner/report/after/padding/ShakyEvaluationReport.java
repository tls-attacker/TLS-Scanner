/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after.padding;

import java.util.List;

public class ShakyEvaluationReport {

    private Boolean consideredVulnerable;

    private final ShakyType shakyType;

    private final Boolean consistentAcrossCvPairs;

    private final List<ShakyVectorHolder> vectorHolderList;

    public ShakyEvaluationReport(Boolean consideredVulnerable, ShakyType shakyType, Boolean consistentAcrossCvPairs, List<ShakyVectorHolder> vectorHolderList) {
        this.consideredVulnerable = consideredVulnerable;
        this.shakyType = shakyType;
        this.consistentAcrossCvPairs = consistentAcrossCvPairs;
        this.vectorHolderList = vectorHolderList;
        if (consideredVulnerable == null || consideredVulnerable == false) {
            for (ShakyVectorHolder holder : vectorHolderList) {
                if (holder.computePValue() < 0.01) {
                    this.consideredVulnerable = true;
                    break;
                }
            }
        }
    }

    public Boolean getConsideredVulnerable() {
        return consideredVulnerable;
    }

    public ShakyType getShakyType() {
        return shakyType;
    }

    public Boolean getConsistentAcrossCvPairs() {
        return consistentAcrossCvPairs;
    }

    public List<ShakyVectorHolder> getVectorHolderList() {
        return vectorHolderList;
    }

}