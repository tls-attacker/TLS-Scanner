/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.util.helper;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.annotation.XmlSeeAlso;

public class UpdatableXmlSeeAlso implements XmlSeeAlso {
    private static final Class<?>[] EMPTY_CLS_ARR = new Class<?>[] {};

    public static Set<Class<?>> patch(Class<?> clazz) {
        XmlSeeAlso origAnnotation = clazz.getAnnotation(XmlSeeAlso.class);
        UpdatableXmlSeeAlso ourAnnotation = new UpdatableXmlSeeAlso(origAnnotation);
        try {
            Field annotationDataField = Class.class.getDeclaredField("annotationData");
            boolean wasAccessible = annotationDataField.isAccessible();
            annotationDataField.setAccessible(true);
            Object annotationData = annotationDataField.get(clazz);
            annotationDataField.setAccessible(wasAccessible);

            Field annotationsField = annotationData.getClass().getDeclaredField("annotations");
            wasAccessible = annotationsField.isAccessible();
            annotationsField.setAccessible(true);
            @SuppressWarnings("unchecked")
            Map<Class<? extends Annotation>, Annotation> annotations = (Map<Class<? extends Annotation>, Annotation>) annotationsField
                    .get(annotationData);
            annotationsField.setAccessible(wasAccessible);

            annotations.put(XmlSeeAlso.class, ourAnnotation);
        } catch (NoSuchFieldException | SecurityException | IllegalAccessException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        return ourAnnotation.value;
    }

    private Set<Class<?>> value;
    private Class<? extends Annotation> annotationType;

    private UpdatableXmlSeeAlso(XmlSeeAlso orig) {
        List<Class<?>> lst = Arrays.asList(orig.value());
        value = new HashSet<>(lst);
        annotationType = orig.annotationType();
    }

    @Override
    public Class<? extends Annotation> annotationType() {
        return annotationType;
    }

    @Override
    public Class[] value() {
        return value.toArray(EMPTY_CLS_ARR);
    }

}
