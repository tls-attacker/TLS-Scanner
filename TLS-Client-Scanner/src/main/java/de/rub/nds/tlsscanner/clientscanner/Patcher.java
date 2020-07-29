package de.rub.nds.tlsscanner.clientscanner;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.Security;
import java.util.Map;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.core.workflow.action.GeneralAction;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.HelloWorldDispatcher;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.StateDispatcher;
import de.rub.nds.tlsscanner.clientscanner.probes.HelloWorldProbe;
import de.rub.nds.tlsscanner.clientscanner.workflow.GetClientHelloMessage;

public class Patcher {
    private static final Logger LOGGER = LogManager.getLogger();

    public static void applyPatches() {
        // from GeneralDelegate.applyDelegate
        Security.addProvider(new BouncyCastleProvider());
        UnlimitedStrengthEnabler.enable();

        patchWorkflowTrace();
    }

    private static class XmlElementInvocationHandler implements InvocationHandler {
        private static Method annotationMethod;
        private static Method nameMethod;
        private static Method typeMethod;

        static {
            try {
                annotationMethod = Annotation.class.getMethod("annotationType");
                nameMethod = XmlElement.class.getMethod("name");
                typeMethod = XmlElement.class.getMethod("type");
            } catch (NoSuchMethodException | SecurityException e) {
                LOGGER.fatal("Failed to patch XmlElement", e);
                throw new RuntimeException("Failed to patch XmlElement", e);
            }
        }

        private String name;
        private Class<?> type;

        public XmlElementInvocationHandler(String name, Class<?> type) {
            this.name = name;
            this.type = type;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            if (method.equals(nameMethod)) {
                return this.name;
            }
            if (method.equals(typeMethod)) {
                return this.type;
            }
            if (method.equals(annotationMethod)) {
                return XmlElement.class;
            }
            return method.getDefaultValue();
        }
    }

    /**
     * Helper function for readability. Creates a Proxy using the
     * XmlElementInvocationHandler, which mimics an XmlElement annotation with
     * changed name and class
     *
     * @param name
     *                 Name to return
     * @param type
     *                 Type to return
     * @return Proxy which behaves like an XmlElement annotation
     */
    private static XmlElement _xmlElement(String name, Class<?> type) {
        return (XmlElement) Proxy.newProxyInstance(
                XmlElement.class.getClassLoader(),
                new Class[] { XmlElement.class },
                new XmlElementInvocationHandler(name, type));
    }

    /**
     * Patch the WorkflowTrace class. To be precise, this patches the annotation for
     * the tlsActions field. This adds some XmlElements to the annotation, such that
     * Actions from this module can be used too.
     */
    private static void patchWorkflowTrace() {
        // mostly based on this answer https://stackoverflow.com/a/32090594/3578387
        try {
            Field field = WorkflowTrace.class.getDeclaredField("tlsActions");
            field.getDeclaredAnnotations();
            XmlElements annotation = field.getDeclaredAnnotation(XmlElements.class);
            XmlElement[] toAdd = {
                    _xmlElement("DHelloWorld", HelloWorldDispatcher.class),
                    _xmlElement("PHelloWorld", HelloWorldProbe.class),
                    _xmlElement("GetCHLO", GetClientHelloMessage.class),
                    //_xmlElement("VersionProbe", VersionProbe.class),
            };

            XmlElement[] newValues = new XmlElement[annotation.value().length + toAdd.length];
            System.arraycopy(annotation.value(), 0, newValues, 0, annotation.value().length);
            System.arraycopy(toAdd, 0, newValues, annotation.value().length, toAdd.length);
            XmlElements newAnnotation = new XmlElements() {
                @Override
                public Class<? extends Annotation> annotationType() {
                    return annotation.annotationType();
                }

                @Override
                public XmlElement[] value() {
                    return newValues;
                }
            };

            Class<?> clazz = field.getClass();
            Field declaredAnnotations = clazz.getDeclaredField("declaredAnnotations");
            boolean accessible = declaredAnnotations.isAccessible();
            declaredAnnotations.setAccessible(true);
            @SuppressWarnings("unchecked")
            Map<Class<? extends Annotation>, Annotation> map = (Map<Class<? extends Annotation>, Annotation>) declaredAnnotations
                    .get(field);
            map.put(XmlElements.class, newAnnotation);
            declaredAnnotations.setAccessible(accessible);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            LOGGER.fatal("Failed to patch WorkflowTrace", e);
            throw new RuntimeException("Failed to patch WorkflowTrace", e);
        }
    }
}