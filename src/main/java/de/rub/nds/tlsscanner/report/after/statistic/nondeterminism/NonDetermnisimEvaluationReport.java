/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after.statistic.nondeterminism;

import java.util.List;

public class NonDetermnisimEvaluationReport {

    private Boolean consideredVulnerable;

    private final NondetermninismType shakyType;

    private final Boolean consistentAcrossCvPairs;

    private final List<NondeterministicVectorContainerHolder> vectorHolderList;

    public NonDetermnisimEvaluationReport(Boolean consideredVulnerable, NondetermninismType shakyType,
            Boolean consistentAcrossCvPairs, List<NondeterministicVectorContainerHolder> vectorHolderList) {
        this.consideredVulnerable = consideredVulnerable;
        this.shakyType = shakyType;
        this.consistentAcrossCvPairs = consistentAcrossCvPairs;
        this.vectorHolderList = vectorHolderList;
        if (consideredVulnerable == null || consideredVulnerable == false) {
            for (NondeterministicVectorContainerHolder holder : vectorHolderList) {
                if (holder.computePValue() < 0.0001) {
                    this.consideredVulnerable = true;
                    break;
                }
            }
            if (consideredVulnerable == null) {
                consideredVulnerable = false;
            }
        }
    }

    public Boolean getConsideredVulnerable() {
        return consideredVulnerable;
    }

    public NondetermninismType getShakyType() {
        return shakyType;
    }

    public Boolean getConsistentAcrossCvPairs() {
        return consistentAcrossCvPairs;
    }

    public List<NondeterministicVectorContainerHolder> getVectorHolderList() {
        return vectorHolderList;
    }

}
