/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.guideline;

/**
 * Key words for use in RFCs to Indicate Requirement Levels.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2119">RFC 2119</a>
 */
public enum RequirementLevel {
    /**
     * This word, or the terms "REQUIRED" or "SHALL", mean that the definition is an absolute
     * requirement of the specification.
     */
    MUST,
    /**
     * This phrase, or the phrase "SHALL NOT", mean that the definition is an absolute prohibition
     * of the specification.
     */
    MUST_NOT,
    /**
     * This word, or the adjective "RECOMMENDED", mean that there may exist valid reasons in
     * particular circumstances to ignore a particular item, but the full implications must be
     * understood and carefully weighed before choosing a different course.
     */
    SHOULD,
    /**
     * This phrase, or the phrase "NOT RECOMMENDED" mean that there may exist valid reasons in
     * particular circumstances when the particular behavior is acceptable or even useful, but the
     * full implications should be understood and the case carefully weighed before implementing any
     * behavior described with this label.
     */
    SHOULD_NOT,
    /**
     * This word, or the adjective "OPTIONAL", mean that an item is truly optional. One vendor may
     * choose to include the item because a particular marketplace requires it or because the vendor
     * feels that it enhances the product while another vendor may omit the same item. An
     * implementation which does not include a particular option MUST be prepared to interoperate
     * with another implementation which does include the option, though perhaps with reduced
     * functionality. In the same vein an implementation which does include a particular option MUST
     * be prepared to interoperate with another implementation which does not include the option
     * (except, of course, for the feature the option provides.)
     */
    MAY
}
