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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Whitelist based on a static file.
 */
public class StaticWhitelist extends EnumeratingWhitelist {

    private static final String[] PERMANENTLY_BLACKLISTED_METHODS = {
        "method java.lang.Runtime exit int",
        "method java.lang.Runtime halt int", };

    private static final String[] PERMANENTLY_BLACKLISTED_STATIC_METHODS = {
        "staticMethod java.lang.System exit int",
        "staticMethod java.lang.System getProperties",
        "staticMethod java.lang.System getProperty java.lang.String",
        "staticMethod java.lang.System getProperty java.lang.String java.lang.String",
        "staticMethod java.lang.System getenv",
        "staticMethod java.lang.System getenv java.lang.String"
    };

    private static final String[] PERMANENTLY_BLACKLISTED_CONSTRUCTORS = {
        "new org.kohsuke.groovy.sandbox.impl.Checker$SuperConstructorWrapper java.lang.Object[]",
        "new org.kohsuke.groovy.sandbox.impl.Checker$ThisConstructorWrapper java.lang.Object[]"
    };

    private final List<MethodSignature> methodSignatures = new ArrayList<>();

    private final List<NewSignature> newSignatures = new ArrayList<>();

    private final List<MethodSignature> staticMethodSignatures = new ArrayList<>();

    private final List<FieldSignature> fieldSignatures = new ArrayList<>();

    private final List<FieldSignature> staticFieldSignatures = new ArrayList<>();

    public StaticWhitelist(final Reader definition) throws IOException {
        try (BufferedReader br = new BufferedReader(definition)) {
            List<String> lines = br.lines().
                    map(StaticWhitelist::filter).
                    filter(Objects::nonNull).
                    collect(Collectors.toList());
            for (String line : lines) {
                add(line);
            }
        }
    }

    public StaticWhitelist(final Collection<? extends String> lines) throws IOException {
        for (String line : lines) {
            add(line);
        }
    }

    public StaticWhitelist(final String... lines) throws IOException {
        this(Arrays.asList(lines));
    }

    /**
     * Filters a line, returning the content that must be processed.
     *
     * @param line Line to filter.
     * @return {@code null} if the like must be skipped or the content to process if not.
     */
    static String filter(final String line) {
        String trimmed = line.trim();
        if (trimmed.isEmpty() || trimmed.startsWith("#")) {
            return null;
        }
        return trimmed;
    }

    /**
     * @param m method
     * @return true if the given method is permanently blacklisted in
     * {@link #PERMANENTLY_BLACKLISTED_METHODS}
     */
    public static boolean isPermanentlyBlacklistedMethod(final Method m) {
        String signature = canonicalMethodSig(m);

        for (String s : PERMANENTLY_BLACKLISTED_METHODS) {
            if (s.equals(signature)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param m method
     * @return true if the given method is permanently blacklisted in
     * {@link #PERMANENTLY_BLACKLISTED_STATIC_METHODS}
     */
    public static boolean isPermanentlyBlacklistedStaticMethod(final Method m) {
        String signature = canonicalStaticMethodSig(m);

        for (String s : PERMANENTLY_BLACKLISTED_STATIC_METHODS) {
            if (s.equals(signature)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param c constructor
     * @return true if the given constructor is permanently blacklisted in
     * {@link #PERMANENTLY_BLACKLISTED_CONSTRUCTORS}
     */
    public static boolean isPermanentlyBlacklistedConstructor(final Constructor<?> c) {
        String signature = canonicalConstructorSig(c);

        for (String s : PERMANENTLY_BLACKLISTED_CONSTRUCTORS) {
            if (s.equals(signature)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse a signature line into a {@link Signature}.
     *
     * @param line The signature string
     * @return the equivalent {@link Signature}
     * @throws IOException if the signature string could not be parsed.
     */
    public static Signature parse(final String line) throws IOException {
        String[] toks = line.split(" ");
        switch (toks[0]) {
            case "method":
                if (toks.length < 3) {
                    throw new IOException(line);
                }
                return new MethodSignature(toks[1], toks[2], Arrays.copyOfRange(toks, 3, toks.length));
            case "new":
                if (toks.length < 2) {
                    throw new IOException(line);
                }
                return new NewSignature(toks[1], Arrays.copyOfRange(toks, 2, toks.length));
            case "staticMethod":
                if (toks.length < 3) {
                    throw new IOException(line);
                }
                return new StaticMethodSignature(toks[1], toks[2], Arrays.copyOfRange(toks, 3, toks.length));
            case "field":
                if (toks.length != 3) {
                    throw new IOException(line);
                }
                return new FieldSignature(toks[1], toks[2]);
            case "staticField":
                if (toks.length != 3) {
                    throw new IOException(line);
                }
                return new StaticFieldSignature(toks[1], toks[2]);
            default:
                throw new IOException(line);
        }
    }

    /**
     * Checks if the signature is permanently blacklisted, and so shouldn't show up in the pending approval list.
     *
     * @param signature the signature to check
     * @return true if the signature is permanently blacklisted, false otherwise.
     */
    public static boolean isPermanentlyBlacklisted(final String signature) {
        for (String s : PERMANENTLY_BLACKLISTED_METHODS) {
            if (s.equals(signature)) {
                return true;
            }
        }
        for (String s : PERMANENTLY_BLACKLISTED_STATIC_METHODS) {
            if (s.equals(signature)) {
                return true;
            }
        }
        for (String s : PERMANENTLY_BLACKLISTED_CONSTRUCTORS) {
            if (s.equals(signature)) {
                return true;
            }
        }

        return false;
    }

    private void add(final String line) throws IOException {
        Signature s = parse(line);
        if (s instanceof StaticMethodSignature) {
            staticMethodSignatures.add((StaticMethodSignature) s);
        } else if (s instanceof MethodSignature) {
            methodSignatures.add((MethodSignature) s);
        } else if (s instanceof StaticFieldSignature) {
            staticFieldSignatures.add((StaticFieldSignature) s);
        } else if (s instanceof FieldSignature) {
            fieldSignatures.add((FieldSignature) s);
        } else {
            newSignatures.add((NewSignature) s);
        }
    }

    public static StaticWhitelist from(final URL definition) throws IOException {
        try (InputStream is = definition.openStream()) {
            return new StaticWhitelist(new InputStreamReader(is, StandardCharsets.UTF_8));
        }
    }

    @Override
    protected List<MethodSignature> methodSignatures() {
        return methodSignatures;
    }

    @Override
    protected List<NewSignature> newSignatures() {
        return newSignatures;
    }

    @Override
    protected List<MethodSignature> staticMethodSignatures() {
        return staticMethodSignatures;
    }

    @Override
    protected List<FieldSignature> fieldSignatures() {
        return fieldSignatures;
    }

    @Override
    protected List<FieldSignature> staticFieldSignatures() {
        return staticFieldSignatures;
    }

    public static SecurityException rejectMethod(final Method m) {
        assert (m.getModifiers() & Modifier.STATIC) == 0;
        return reject("method " + EnumeratingWhitelist.getName(m.getDeclaringClass()) + " " + m.getName()
                + printArgumentTypes(m.getParameterTypes()));
    }

    public static SecurityException rejectMethod(final Method m, final String info) {
        assert (m.getModifiers() & Modifier.STATIC) == 0;
        return reject("method " + EnumeratingWhitelist.getName(m.getDeclaringClass()) + " " + m.getName()
                + printArgumentTypes(m.getParameterTypes()) + " (" + info + ")");
    }

    public static SecurityException rejectNew(final Constructor<?> c) {
        return reject("new " + EnumeratingWhitelist.getName(c.getDeclaringClass())
                + printArgumentTypes(c.getParameterTypes()));
    }

    public static SecurityException rejectStaticMethod(final Method m) {
        assert (m.getModifiers() & Modifier.STATIC) != 0;
        return reject("staticMethod " + EnumeratingWhitelist.getName(m.getDeclaringClass()) + " " + m.getName()
                + printArgumentTypes(m.getParameterTypes()));
    }

    public static SecurityException rejectField(final Field f) {
        assert (f.getModifiers() & Modifier.STATIC) == 0;
        return reject("field " + EnumeratingWhitelist.getName(f.getDeclaringClass()) + " " + f.getName());
    }

    public static SecurityException rejectStaticField(final Field f) {
        assert (f.getModifiers() & Modifier.STATIC) != 0;
        return reject("staticField " + EnumeratingWhitelist.getName(f.getDeclaringClass()) + " " + f.getName());
    }

    private static SecurityException reject(final String detail) {
        return new SecurityException("Insecure call to '" + detail + "' you can tweak the security "
                + "sandbox to allow it. Read more about this in the documentation.");
    }

    private static String printArgumentTypes(final Class<?>[] parameterTypes) {
        StringBuilder b = new StringBuilder();
        for (Class<?> c : parameterTypes) {
            b.append(' ');
            b.append(EnumeratingWhitelist.getName(c));
        }
        return b.toString();
    }
}
