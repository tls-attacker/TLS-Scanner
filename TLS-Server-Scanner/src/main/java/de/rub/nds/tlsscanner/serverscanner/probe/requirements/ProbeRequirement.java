/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.requirements;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class ProbeRequirement implements Requirement {
    private ServerReport report;
    private TlsProbeType[] requiredProbeTypes;
    private TlsAnalyzedProperty[] requiredAnalyzedproperties, requiredAnalyzedpropertiesNot;
    private ExtensionType[] requiredExtensionTypes;
    private ProtocolVersion[] requiredProtocolVersions;
    private ProbeRequirement not;
    private ProbeRequirement[] requiredOR;

    public static ProbeRequirement NO_REQUIREMENT = new ProbeRequirement(null);

    public ProbeRequirement(ServerReport report) {
        this.report = report;
    }

    public ProbeRequirement getMissingRequirements() {
        ProbeRequirement missing = new ProbeRequirement(this.report);

        if (this.requiredProbeTypes != null) {
            List<TlsProbeType> ptypes = new LinkedList<>();
            for (TlsProbeType pt : this.requiredProbeTypes) {
                if (report.isProbeAlreadyExecuted(pt) == false)
                    ptypes.add(pt);
            }
            TlsProbeType[] tpt = new TlsProbeType[ptypes.size()];
            Iterator<TlsProbeType> it = ptypes.iterator();
            for (int i = 0; i < ptypes.size(); i++)
                tpt[i] = it.next();
            missing.requireProbeTypes(tpt);
        }

        if (this.requiredAnalyzedproperties != null) {
            List<TlsAnalyzedProperty> aprops = new LinkedList<>();
            Map<String, TestResult> apList = report.getResultMap();
            for (TlsAnalyzedProperty ap : this.requiredAnalyzedproperties) {
                if (apList.containsKey(ap.toString()) || apList.get(ap.toString()) != TestResults.TRUE)
                    aprops.add(ap);
            }
            TlsAnalyzedProperty[] tap = new TlsAnalyzedProperty[aprops.size()];
            Iterator<TlsAnalyzedProperty> it = aprops.iterator();
            for (int i = 0; i < aprops.size(); i++)
                tap[i] = it.next();
            missing.requireAnalyzedProperties(tap);
        }

        if (this.requiredProtocolVersions != null) {
            List<ProtocolVersion> pvList = report.getVersions();
            if (pvList == null)
                missing.requireProtocolVersions(this.requiredProtocolVersions);
            else {
                List<ProtocolVersion> pvers = new LinkedList<>();
                for (ProtocolVersion pv : this.requiredProtocolVersions) {
                    if (!pvList.contains(pv))
                        pvers.add(pv);
                }
                ProtocolVersion[] pva = new ProtocolVersion[pvers.size()];
                Iterator<ProtocolVersion> it = pvers.iterator();
                for (int i = 0; i < pvers.size(); i++)
                    pva[i] = it.next();
                missing.requireProtocolVersions(pva);
            }
        }

        if (this.requiredAnalyzedpropertiesNot != null) {
            List<TlsAnalyzedProperty> aprops = new LinkedList<>();
            Map<String, TestResult> apList = report.getResultMap();
            for (TlsAnalyzedProperty ap : this.requiredAnalyzedpropertiesNot) {
                if (apList.containsKey(ap.toString()) || apList.get(ap.toString()) != TestResults.FALSE)
                    aprops.add(ap);
            }
            TlsAnalyzedProperty[] tap = new TlsAnalyzedProperty[aprops.size()];
            Iterator<TlsAnalyzedProperty> it = aprops.iterator();
            for (int i = 0; i < aprops.size(); i++)
                tap[i] = it.next();
            missing.requireAnalyzedPropertiesNot(tap);
        }

        if (this.requiredExtensionTypes != null) {
            List<ExtensionType> etList = report.getSupportedExtensions();
            if (etList == null)
                missing.requireExtensionTyes(this.requiredExtensionTypes);
            else {
                List<ExtensionType> etype = new LinkedList<>();
                for (ExtensionType et : this.requiredExtensionTypes) {
                    if (!etList.contains(et))
                        etype.add(et);
                }
                ExtensionType[] eta = new ExtensionType[etype.size()];
                Iterator<ExtensionType> it = etype.iterator();
                for (int i = 0; i < etype.size(); i++)
                    eta[i] = it.next();
                missing.requireExtensionTyes(eta);
            }
        }

        if (this.requiredOR != null) {
            boolean or = false;
            for (ProbeRequirement pReq : this.requiredOR) {
                if (pReq.evaluateRequirements()) {
                    or = true;
                    break;
                }
            }
            if (!or)
                missing.orRequirement(this.requiredOR);
        }

        if (this.not != null && not.evaluateRequirements())
            missing.notRequirement(this.not);

        return missing;
    }

    public ProbeRequirement requireProbeTypes(TlsProbeType... probeTypes) {
        this.requiredProbeTypes = probeTypes;
        return this;
    }

    public ProbeRequirement requireProtocolVersions(ProtocolVersion... protocolVersions) {
        this.requiredProtocolVersions = protocolVersions;
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

    public ProbeRequirement requireExtensionTyes(ExtensionType... extensionTypes) {
        this.requiredExtensionTypes = extensionTypes;
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
        return probeTypesFulfilled() && analyzedProtocolVersionsFulfilled() && analyzedPropertiesFulfilled()
            && extensionTypesFulfilled() && orFulfilled() && notFulfilled() && analyzedPropertiesNotFulfilled();
    }

    private boolean probeTypesFulfilled() {
        if (this.requiredProbeTypes == null)
            return true;
        for (TlsProbeType pt : this.requiredProbeTypes) {
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

    private boolean analyzedProtocolVersionsFulfilled() {
        if (this.requiredProtocolVersions == null)
            return true;
        List<ProtocolVersion> pvList = report.getVersions();
        if (pvList == null)
            return false;
        for (ProtocolVersion pv : this.requiredProtocolVersions) {
            if (!pvList.contains(pv))
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

    private boolean extensionTypesFulfilled() {
        if (this.requiredExtensionTypes == null)
            return true;
        List<ExtensionType> etList = report.getSupportedExtensions();
        if (etList == null)
            return false;
        for (ExtensionType et : this.requiredExtensionTypes) {
            if (!etList.contains(et))
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
     * @return the requiredExtensionTypes
     */
    public ExtensionType[] getRequiredExtensionTypes() {
        return this.requiredExtensionTypes;
    }

    /**
     * @return the requiredProtocolVersions
     */
    public ProtocolVersion[] getRequiredProtocolVersions() {
        return this.requiredProtocolVersions;
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
