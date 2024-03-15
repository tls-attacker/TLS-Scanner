/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.report.rating;

import de.rub.nds.scanner.core.constants.AnalyzedProperty;
import de.rub.nds.scanner.core.io.JAXBIO;
import jakarta.xml.bind.JAXBException;
import java.util.Set;

public class RecommendationsIO extends JAXBIO<Recommendations> {

    public RecommendationsIO(Class<? extends AnalyzedProperty> analyzedPropertyClass)
            throws JAXBException {
        super(
                Set.of(
                        Recommendations.class,
                        Recommendation.class,
                        PropertyResultRecommendation.class,
                        analyzedPropertyClass));
    }
}
