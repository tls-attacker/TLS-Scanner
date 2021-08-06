/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.reflections.ReflectionUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Objects;
import java.util.Set;
import java.util.StringJoiner;

public abstract class GuidelineCheck {

    private String name;
    private String description;
    private RequirementLevel requirementLevel;

    public abstract void evaluate(SiteReport report, GuidelineCheckResult result);

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public RequirementLevel getRequirementLevel() {
        return requirementLevel;
    }

    public void setRequirementLevel(RequirementLevel requirementLevel) {
        this.requirementLevel = requirementLevel;
    }

    @SuppressWarnings("unchecked")
    public String getId() {
        Set<Field> fields = ReflectionUtils.getAllFields(this.getClass());
        fields.removeAll(ReflectionUtils.getFields(GuidelineCheck.class));
        StringJoiner joiner = new StringJoiner("_");
        joiner.add(this.getClass().getSimpleName()).add(String.valueOf(requirementLevel));
        for (Field field : fields) {
            if (Modifier.isStatic(field.getModifiers())) {
                continue;
            }
            field.setAccessible(true);
            try {
                Object result = field.get(this);
                if (result != null) {
                    joiner.add(String.valueOf(field.get(this)));
                }
            } catch (IllegalAccessException ignored) {
            }
        }
        return joiner.toString();
    }
}
