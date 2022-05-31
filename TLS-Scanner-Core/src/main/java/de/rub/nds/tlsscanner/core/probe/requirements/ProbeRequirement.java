/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class ProbeRequirement implements Requirement {
    private TlsProbeType[] requiredProbeTypes;
    private TlsAnalyzedProperty[] requiredAnalyzedproperties, requiredAnalyzedpropertiesNot;
    private ExtensionType[] requiredExtensionTypes;
    private ProtocolVersion[] requiredProtocolVersions;
    private ProbeRequirement not;
    private ProbeRequirement[] requiredOR;

    public static ProbeRequirement NO_REQUIREMENT = new ProbeRequirement();

    public ProbeRequirement() {
    }

    public ProbeRequirement getMissingRequirements(ScanReport report) {
        ProbeRequirement missing = new ProbeRequirement();

        if (requiredProbeTypes != null) {
            List<TlsProbeType> ptypes = new LinkedList<>();
            for (TlsProbeType pt : requiredProbeTypes) {
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
            for (TlsAnalyzedProperty ap : requiredAnalyzedproperties) {
                if (apList.containsKey(ap.toString()) && apList.get(ap.toString()) != TestResults.TRUE)
                    aprops.add(ap);
            }
            TlsAnalyzedProperty[] tap = new TlsAnalyzedProperty[aprops.size()];
            Iterator<TlsAnalyzedProperty> it = aprops.iterator();
            for (int i = 0; i < aprops.size(); i++)
                tap[i] = it.next();
            missing.requireAnalyzedProperties(tap);
        }

        if (requiredProtocolVersions != null) {
            TestResult versionsuiteResult =
                report.getResultMap().get(TlsAnalyzedProperty.LIST_VERSIONSUITE_PAIRS.name());
            if (versionsuiteResult != null) {
                @SuppressWarnings("unchecked")
                List<ProtocolVersion> pvList = ((ListResult<ProtocolVersion>) versionsuiteResult).getList();
                if (pvList != null && !pvList.isEmpty()) {
                    List<ProtocolVersion> pvers = new LinkedList<>();
                    for (ProtocolVersion pv : requiredProtocolVersions) {
                        if (!pvList.contains(pv))
                            pvers.add(pv);
                    }
                    ProtocolVersion[] pva = new ProtocolVersion[pvers.size()];
                    Iterator<ProtocolVersion> it = pvers.iterator();
                    for (int i = 0; i < pvers.size(); i++)
                        pva[i] = it.next();
                    missing.requireProtocolVersions(pva);
                } else
                    missing.requireProtocolVersions(requiredProtocolVersions);
            } else
                missing.requireProtocolVersions(requiredProtocolVersions);
        }

        if (requiredAnalyzedpropertiesNot != null) {
            List<TlsAnalyzedProperty> aprops = new LinkedList<>();
            Map<String, TestResult> apList = report.getResultMap();
            for (TlsAnalyzedProperty ap : requiredAnalyzedpropertiesNot) {
                if (apList.containsKey(ap.toString()) && apList.get(ap.toString()) != TestResults.FALSE)
                    aprops.add(ap);
            }
            TlsAnalyzedProperty[] tap = new TlsAnalyzedProperty[aprops.size()];
            Iterator<TlsAnalyzedProperty> it = aprops.iterator();
            for (int i = 0; i < aprops.size(); i++)
                tap[i] = it.next();
            missing.requireAnalyzedPropertiesNot(tap);
        }

        if (requiredExtensionTypes != null) {
            TestResult extensionResult =
                report.getResultMap().get(TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS.name());
            if (extensionResult != null) {
                @SuppressWarnings("unchecked")
                List<ExtensionType> etList = ((ListResult<ExtensionType>) extensionResult).getList();
                if (etList != null && !etList.isEmpty()) {
                    List<ExtensionType> etype = new LinkedList<>();
                    for (ExtensionType et : requiredExtensionTypes) {
                        if (!etList.contains(et))
                            etype.add(et);
                    }
                    ExtensionType[] eta = new ExtensionType[etype.size()];
                    Iterator<ExtensionType> it = etype.iterator();
                    for (int i = 0; i < etype.size(); i++)
                        eta[i] = it.next();
                    missing.requireExtensionTyes(eta);
                } else
                    missing.requireExtensionTyes(requiredExtensionTypes);
            } else
                missing.requireExtensionTyes(requiredExtensionTypes);
        }

        if (requiredOR != null) {
            boolean or = false;
            for (ProbeRequirement pReq : requiredOR) {
                if (pReq.evaluate(report)) {
                    or = true;
                    break;
                }
            }
            if (!or)
                missing.orRequirement(requiredOR);
        }

        if (not != null && not.evaluate(report))
            missing.notRequirement(not);

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

    public boolean evaluate(ScanReport report) {
        return probeTypesFulfilled(report) && analyzedProtocolVersionsFulfilled(report)
            && analyzedPropertiesFulfilled(report) && extensionTypesFulfilled(report) && orFulfilled(report)
            && notFulfilled(report) && analyzedPropertiesNotFulfilled(report);
    }

    private boolean probeTypesFulfilled(ScanReport report) {
        if (requiredProbeTypes == null)
            return true;
        for (TlsProbeType pt : requiredProbeTypes) {
            if (report.isProbeAlreadyExecuted(pt) == false)
                return false;
        }
        return true;
    }

    private boolean analyzedPropertiesFulfilled(ScanReport report) {
        if (requiredAnalyzedproperties == null)
            return true;
        Map<String, TestResult> apList = report.getResultMap();
        for (TlsAnalyzedProperty ap : requiredAnalyzedproperties) {
            if (apList.containsKey(ap.toString())) {
                if (apList.get(ap.toString()) != TestResults.TRUE)
                    return false;
            } else
                return false;
        }
        return true;
    }

    private boolean analyzedProtocolVersionsFulfilled(ScanReport report) {
        if (requiredProtocolVersions == null)
            return true;
        TestResult versionsuiteResult =
            report.getResultMap().get(TlsAnalyzedProperty.LIST_SUPPORTED_PROTOCOLVERSIONS.name());
        if (versionsuiteResult != null) {
            @SuppressWarnings("unchecked")
            List<ProtocolVersion> pvList = ((ListResult<ProtocolVersion>) versionsuiteResult).getList();
            if (pvList != null && !pvList.isEmpty()) {
                for (ProtocolVersion pv : requiredProtocolVersions) {
                    if (pvList.contains(pv))
                        return true;
                }
            }
        }
        return false;
    }

    private boolean analyzedPropertiesNotFulfilled(ScanReport report) {
        if (requiredAnalyzedpropertiesNot == null)
            return true;
        Map<String, TestResult> apList = report.getResultMap();
        for (TlsAnalyzedProperty ap : requiredAnalyzedpropertiesNot) {
            if (apList.containsKey(ap.toString())) {
                if (apList.get(ap.toString()) != TestResults.FALSE)
                    return false;
            } else
                return false;
        }
        return true;
    }

    private boolean extensionTypesFulfilled(ScanReport report) {
        if (requiredExtensionTypes == null)
            return true;
        TestResult extensionResult = report.getResultMap().get(TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS.name());
        if (extensionResult != null) {
            @SuppressWarnings("unchecked")
            List<ExtensionType> etList = ((ListResult<ExtensionType>) extensionResult).getList();
            if (etList != null && !etList.isEmpty()) {
                for (ExtensionType et : requiredExtensionTypes) {
                    if (etList.contains(et))
                        return true;
                }
            }
        }
        return false;
    }

    private boolean orFulfilled(ScanReport report) {
        if (requiredOR == null)
            return true;
        for (ProbeRequirement pReq : requiredOR) {
            if (pReq.evaluate(report))
                return true;
        }
        return false;
    }

    private boolean notFulfilled(ScanReport report) {
        if (not == null)
            return true;
        return !not.evaluate(report);
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
        return requiredAnalyzedproperties;
    }

    /**
     * @return the requiredAnalyzedpropertiesNot
     */
    public TlsAnalyzedProperty[] getRequiredAnalyzedpropertiesNot() {
        return requiredAnalyzedpropertiesNot;
    }

    /**
     * @return the requiredExtensionTypes
     */
    public ExtensionType[] getRequiredExtensionTypes() {
        return requiredExtensionTypes;
    }

    /**
     * @return the requiredProtocolVersions
     */
    public ProtocolVersion[] getRequiredProtocolVersions() {
        return requiredProtocolVersions;
    }

    /**
     * @return the or ProbeRequirements
     */
    public ProbeRequirement[] getORRequirements() {
        return requiredOR;
    }

    /**
     * @return the inverted ProbeRequirement
     */
    public ProbeRequirement getNot() {
        return not;
    }
}
