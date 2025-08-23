/*
 * Copyright 2014 CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.lang3.ClassUtils;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;

/**
 * A whitelist based on listing signatures and searching them. Lists of signatures should not change
 * from invocation to invocation.
 *
 * If that's a need it is better to directly extend {@link Whitelist} and roll a custom implementation OR
 * extend ProxyWhitelist and add some custom delegates.
 */
public abstract class EnumeratingWhitelist extends Whitelist {

    protected final ConcurrentHashMap<String, Boolean> permittedCache = new ConcurrentHashMap<>();

    protected abstract List<MethodSignature> methodSignatures();

    protected abstract List<NewSignature> newSignatures();

    protected abstract List<MethodSignature> staticMethodSignatures();

    protected abstract List<FieldSignature> fieldSignatures();

    protected abstract List<FieldSignature> staticFieldSignatures();

    @Override
    public boolean permitsMethod(final Method method, final Object receiver, final Object[] args) {
        String key = canonicalMethodSig(method);
        Boolean b = permittedCache.get(key);
        if (b != null) {
            return b;
        }

        boolean output = false;
        for (MethodSignature s : methodSignatures()) {
            if (s.matches(method)) {
                output = true;
                break;
            }
        }
        permittedCache.put(key, output);
        return output;
    }

    @Override
    public boolean permitsConstructor(final Constructor<?> constructor, final Object[] args) {
        String key = canonicalConstructorSig(constructor);
        Boolean b = permittedCache.get(key);
        if (b != null) {
            return b;
        }

        boolean output = false;
        for (NewSignature s : newSignatures()) {
            if (s.matches(constructor)) {
                output = true;
                break;
            }
        }
        permittedCache.put(key, output);
        return output;
    }

    @Override
    public boolean permitsStaticMethod(final Method method, final Object[] args) {
        String key = canonicalStaticMethodSig(method);
        Boolean b = permittedCache.get(key);
        if (b != null) {
            return b;
        }

        boolean output = false;
        for (MethodSignature s : staticMethodSignatures()) {
            if (s.matches(method)) {
                output = true;
                break;
            }
        }
        permittedCache.put(key, output);
        return output;
    }

    @Override
    public boolean permitsFieldGet(final Field field, final Object receiver) {
        String key = canonicalFieldSig(field);
        Boolean b = permittedCache.get(key);
        if (b != null) {
            return b;
        }

        boolean output = false;
        for (FieldSignature s : fieldSignatures()) {
            if (s.matches(field)) {
                output = true;
                break;
            }
        }
        permittedCache.put(key, output);
        return output;
    }

    @Override
    public boolean permitsFieldSet(final Field field, final Object receiver, final Object value) {
        return permitsFieldGet(field, receiver);
    }

    @Override
    public boolean permitsStaticFieldGet(final Field field) {
        String key = canonicalStaticFieldSig(field);
        Boolean b = permittedCache.get(key);
        if (b != null) {
            return b;
        }

        boolean output = false;
        for (FieldSignature s : staticFieldSignatures()) {
            if (s.matches(field)) {
                output = true;
                break;
            }
        }
        permittedCache.put(key, output);
        return output;
    }

    @Override
    public boolean permitsStaticFieldSet(final Field field, final Object value) {
        return permitsStaticFieldGet(field);
    }

    public static String getName(final Class<?> c) {
        Class<?> e = c.getComponentType();
        if (e == null) {
            return c.getName();
        }
        return getName(e) + "[]";
    }

    public static String getName(final Object o) {
        return o == null ? "null" : getName(o.getClass());
    }

    private static boolean is(final String thisIdentifier, final String identifier) {
        return thisIdentifier.equals("*") || identifier.equals(thisIdentifier);
    }

    public abstract static class Signature implements Comparable<Signature> {

        /**
         * @return Form as in {@link StaticWhitelist} entries.
         */
        @Override
        public abstract String toString();

        protected abstract String signaturePart();

        @Override
        public int compareTo(final Signature signature) {
            int r = signaturePart().compareTo(signature.signaturePart());
            return r != 0 ? r : toString().compareTo(signature.toString());
        }

        @Override
        public boolean equals(final Object obj) {
            return obj != null && obj.getClass() == getClass() && toString().equals(obj.toString());
        }

        @Override
        public int hashCode() {
            return toString().hashCode();
        }

        protected abstract boolean exists() throws Exception;

        final Class<?> type(final String name) throws Exception {
            return ClassUtils.getClass(name);
        }

        final Class<?>[] types(final String[] names) throws Exception {
            Class<?>[] r = new Class<?>[names.length];
            for (int i = 0; i < names.length; i++) {
                r[i] = type(names[i]);
            }
            return r;
        }

        public boolean isWildcard() {
            return false;
        }
    }

    // Utility methods for creating canonical string representations of the signature
    static final StringBuilder joinWithSpaces(final StringBuilder b, final String[] types) {
        for (String type : types) {
            b.append(' ').append(type);
        }
        return b;
    }

    static String[] argumentTypes(final Class<?>[] argumentTypes) {
        String[] s = new String[argumentTypes.length];
        for (int i = 0; i < argumentTypes.length; i++) {
            s[i] = getName(argumentTypes[i]);
        }
        return s;
    }

    /**
     * Canonical name for a field access.
     */
    static String canonicalFieldString(final Field field) {
        return getName(field.getDeclaringClass()) + ' ' + field.getName();
    }

    /**
     * Canonical name for a method call.
     */
    static String canonicalMethodString(final Method method) {
        return joinWithSpaces(new StringBuilder(getName(method.getDeclaringClass())).append(' ').
                append(method.getName()), argumentTypes(method.getParameterTypes())).toString();
    }

    /**
     * Canonical name for a constructor call.
     */
    static String canonicalConstructorString(final Constructor<?> cons) {
        return joinWithSpaces(new StringBuilder(getName(cons.getDeclaringClass())), argumentTypes(cons.
                getParameterTypes())).toString();
    }

    static String canonicalMethodSig(final Method method) {
        return "method " + canonicalMethodString(method);
    }

    static String canonicalStaticMethodSig(final Method method) {
        return "staticMethod " + canonicalMethodString(method);
    }

    static String canonicalConstructorSig(final Constructor<?> cons) {
        return "new " + canonicalConstructorString(cons);
    }

    static String canonicalFieldSig(final Field field) {
        return "field " + canonicalFieldString(field);
    }

    static String canonicalStaticFieldSig(final Field field) {
        return "staticField " + canonicalFieldString(field);
    }

    public static class MethodSignature extends Signature {

        protected final String receiverType, method;

        protected final String[] argumentTypes;

        public MethodSignature(
                final Class<?> receiverType,
                final String method,
                final Class<?>... argumentTypes) {

            this(getName(receiverType), method, argumentTypes(argumentTypes));
        }

        public MethodSignature(
                final String receiverType,
                final String method,
                final String[] argumentTypes) {

            this.receiverType = receiverType;
            this.method = method;
            this.argumentTypes = argumentTypes.clone();
        }

        protected boolean matches(final Method m) {
            return is(method, m.getName())
                    && getName(m.getDeclaringClass()).equals(receiverType)
                    && Arrays.equals(argumentTypes(m.getParameterTypes()), argumentTypes);
        }

        @Override
        public String toString() {
            return "method " + signaturePart();
        }

        @Override
        protected String signaturePart() {
            return joinWithSpaces(new StringBuilder(receiverType).append(' ').append(method), argumentTypes).toString();
        }

        @Override
        protected boolean exists() throws Exception {
            return exists(type(receiverType), true);
        }

        // Cf. GroovyCallSiteSelector.visitTypes.
        @SuppressWarnings("InfiniteRecursion")
        private boolean exists(final Class<?> c, final boolean start) throws Exception {
            Class<?> s = c.getSuperclass();
            if (s != null && exists(s, false)) {
                return !start;
            }
            for (Class<?> i : c.getInterfaces()) {
                if (exists(i, false)) {
                    return !start;
                }
            }
            try {
                return !Modifier.isStatic(c.getDeclaredMethod(method, types(argumentTypes)).getModifiers());
            } catch (NoSuchMethodException x) {
                return false;
            }
        }

        @Override
        public boolean isWildcard() {
            return "*".equals(method);
        }
    }

    public static class StaticMethodSignature extends MethodSignature {

        StaticMethodSignature(final String receiverType, final String method, final String[] argumentTypes) {
            super(receiverType, method, argumentTypes);
        }

        @Override
        public String toString() {
            return "staticMethod " + signaturePart();
        }

        @Override
        protected boolean exists() throws Exception {
            try {
                return Modifier.isStatic(
                        type(receiverType).getDeclaredMethod(method, types(argumentTypes)).getModifiers());
            } catch (NoSuchMethodException x) {
                return false;
            }
        }
    }

    public static final class NewSignature extends Signature {

        private final String type;

        private final String[] argumentTypes;

        public NewSignature(final String type, final String[] argumentTypes) {
            this.type = type;
            this.argumentTypes = argumentTypes.clone();
        }

        public NewSignature(final Class<?> type, final Class<?>... argumentTypes) {
            this(getName(type), argumentTypes(argumentTypes));
        }

        protected boolean matches(final Constructor<?> c) {
            return getName(c.getDeclaringClass()).equals(type)
                    && Arrays.equals(argumentTypes(c.getParameterTypes()), argumentTypes);
        }

        @Override
        protected String signaturePart() {
            return joinWithSpaces(new StringBuilder(type), argumentTypes).toString();
        }

        @Override
        public String toString() {
            return "new " + signaturePart();
        }

        @Override
        protected boolean exists() throws Exception {
            try {
                type(type).getDeclaredConstructor(types(argumentTypes));
                return true;
            } catch (NoSuchMethodException x) {
                return false;
            }
        }
    }

    public static class FieldSignature extends Signature {

        private final String type, field;

        public FieldSignature(final String type, final String field) {
            this.type = type;
            this.field = field;
        }

        public FieldSignature(final Class<?> type, final String field) {
            this(getName(type), field);
        }

        boolean matches(final Field f) {
            return is(field, f.getName()) && getName(f.getDeclaringClass()).equals(type);
        }

        @Override
        protected String signaturePart() {
            return type + ' ' + field;
        }

        @Override
        public String toString() {
            return "field " + signaturePart();
        }

        @Override
        protected boolean exists() throws Exception {
            try {
                type(type).getField(field);
                return true;
            } catch (NoSuchFieldException x) {
                return false;
            }
        }

        @Override
        public boolean isWildcard() {
            return "*".equals(field);
        }
    }

    public static class StaticFieldSignature extends FieldSignature {

        public StaticFieldSignature(final String type, final String field) {
            super(type, field);
        }

        @Override
        public String toString() {
            return "staticField " + signaturePart();
        }
    }
}
