package de.rub.nds.tlsscanner.clientscanner.probe.requirements;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.Map;

public class ProbeRequirement implements Requirement {
    private ClientReport report;
    private TlsProbeType[] requiredProbeTypes;
    private TlsAnalyzedProperty[] requiredAnalyzedproperties, requiredAnalyzedpropertiesNot;
    private ProbeRequirement not;
    private ProbeRequirement[] requiredOR;

    public ProbeRequirement(ClientReport report) {
        this.report = report;
    }

    public ProbeRequirement requireProbeTypes(TlsProbeType... probeTypes) {
        this.requiredProbeTypes = probeTypes;
        return this;
    }

    public ProbeRequirement requireAnalyzedProperties(TlsAnalyzedProperty... analyzedProperties) {
        this.requiredAnalyzedproperties = analyzedProperties;
        return this;
    }

    public ProbeRequirement requireAnalyzedPropertiesNot(TlsAnalyzedProperty... analyzedPropertiesNot) {
        this.requiredAnalyzedpropertiesNot = analyzedPropertiesNot;
        return this;
    }

    public ProbeRequirement orRequirement(ProbeRequirement... orReq) {
        this.requiredOR = orReq;
        return this;
    }

    public ProbeRequirement notRequirement(ProbeRequirement req) {
        this.not = req;
        return this;
    }

    public boolean evaluateRequirements() {
        return probeTypesFulfilled() && analyzedPropertiesFulfilled() && orFulfilled() 
        		&& notFulfilled() && analyzedPropertiesNotFulfilled();
    }

    private boolean probeTypesFulfilled() {
        if (this.requiredProbeTypes == null)
            return true;
        for (ProbeType pt : this.requiredProbeTypes) {
            if (report.isProbeAlreadyExecuted(pt) == false)
                return false;
        }
        return true;
    }

    private boolean analyzedPropertiesFulfilled() {
        if (this.requiredAnalyzedproperties == null)
            return true;
        Map<String, TestResult> apList = report.getResultMap();
        for (TlsAnalyzedProperty ap : this.requiredAnalyzedproperties) {
            if (apList.containsKey(ap.toString())) {
                if (apList.get(ap.toString()) != TestResults.TRUE)
                    return false;
            } else
                return false;
        }
        return true;
    }

    private boolean analyzedPropertiesNotFulfilled() {
        if (this.requiredAnalyzedpropertiesNot == null)
            return true;
        Map<String, TestResult> apList = report.getResultMap();
        for (TlsAnalyzedProperty ap : this.requiredAnalyzedpropertiesNot) {
            if (apList.containsKey(ap.toString())) {
                if (apList.get(ap.toString()) != TestResults.FALSE)
                    return false;
            } else
                return false;
        }
        return true;
    }

    private boolean orFulfilled() {
        if (this.requiredOR == null)
            return true;
        for (ProbeRequirement pReq : this.requiredOR) {
            if (pReq.evaluateRequirements())
                return true;
        }
        return false;
    }

    private boolean notFulfilled() {
        if (this.not == null)
            return true;
        return !this.not.evaluateRequirements();
    }

    /**
     * @return the requiredProbeTypes
     */
    public TlsProbeType[] getRequiredProbeTypes() {
        return requiredProbeTypes;
    }

    /**
     * @return the requiredAnalyzedproperties
     */
    public TlsAnalyzedProperty[] getRequiredAnalyzedproperties() {
        return this.requiredAnalyzedproperties;
    }

    /**
     * @return the requiredAnalyzedpropertiesNot
     */
    public TlsAnalyzedProperty[] getRequiredAnalyzedpropertiesNot() {
        return this.requiredAnalyzedpropertiesNot;
    }

    /**
     * @return the or ProbeRequirements
     */
    public ProbeRequirement[] getORRequirements() {
        return this.requiredOR;
    }

    /**
     * @return the inverted ProbeRequirement
     */
    public ProbeRequirement getNot() {
        return this.not;
    }
}