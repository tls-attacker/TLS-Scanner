/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.guideline;

import de.rub.nds.scanner.core.constants.AnalyzedProperty;
import de.rub.nds.scanner.core.io.JAXBIO;
import de.rub.nds.scanner.core.report.ScanReport;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import java.util.HashSet;
import java.util.Set;

public final class GuidelineIO<R extends ScanReport<R>> extends JAXBIO<Guideline<R>> {

    public GuidelineIO(
            Class<? extends AnalyzedProperty> analyzedPropertyClass,
            Set<Class<? extends GuidelineCheck<R>>> supportedGuidelineCheckClasses)
            throws JAXBException {
        this.context = getJAXBContext(analyzedPropertyClass, supportedGuidelineCheckClasses);
    }

    private JAXBContext getJAXBContext(
            Class<? extends AnalyzedProperty> analyzedPropertyClass,
            Set<Class<? extends GuidelineCheck<R>>> supportedGuidelineCheckClasses)
            throws JAXBException {
        Set<Class<?>> classesToBeBound = new HashSet<>(supportedGuidelineCheckClasses);
        classesToBeBound.add(analyzedPropertyClass);
        classesToBeBound.add(Guideline.class);
        return getJAXBContext(classesToBeBound);
    }
}
