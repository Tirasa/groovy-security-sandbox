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
package org.jenkinsci.plugins.scriptsecurity.sandbox;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Determines which methods and similar members which scripts may call.
 */
public abstract class Whitelist {

    private static final Logger LOG = Logger.getLogger(Whitelist.class.getName());

    private List<String> getEnvWhitelistRegex = new ArrayList<>();

    /**
     * Cache the System.getenv method for comparing
     */
    private Method getenvMethod;

    public Whitelist() {
        try {
            this.getenvMethod = System.class.getMethod("getenv", String.class);
        } catch (NoSuchMethodException e) {
            LOG.log(Level.WARNING, "No such method 'getenv' in class 'System'.", e);
        }
    }

    /**
     * Set a list of regex of environment variables name that is allowed to be called
     *
     * @param getEnvWhitelistRegex the regex list
     */
    public void setGetEnvWhitelistRegex(final List<String> getEnvWhitelistRegex) {
        this.getEnvWhitelistRegex = getEnvWhitelistRegex;
    }

    /**
     * Return true if the given method is allowed System.getEnv()
     *
     * @param m the method
     * @param args the method arguments
     * @return true if allowed, false otherwise
     */
    public boolean isAllowedGetEnvSystemMethod(final Method m, final Object[] args) {
        if (m.equals(getenvMethod)) {
            String envName = (String) args[0];
            // Match the envName against the regex
            for (String regex : getEnvWhitelistRegex) {
                if (Pattern.matches(regex, envName)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Checks whether a given virtual method may be invoked.
     * <p>
     * Note that {@code method} should not be implementing or overriding a method in a supertype;
     * in such a case the caller must pass that supertype method instead.
     * In other words, call site selection is the responsibility of the caller (such as {@code GroovySandbox}), not the
     * whitelist.
     *
     * @param method a method defined in the JVM
     * @param receiver {@code this}, the receiver of the method call
     * @param args zero or more arguments
     * @return true to allow the method to be called, false to reject it
     */
    public abstract boolean permitsMethod(Method method, Object receiver, Object[] args);

    public abstract boolean permitsConstructor(Constructor<?> constructor, Object[] args);

    public abstract boolean permitsStaticMethod(Method method, Object[] args);

    public abstract boolean permitsFieldGet(Field field, Object receiver);

    public abstract boolean permitsFieldSet(Field field, Object receiver, Object value);

    public abstract boolean permitsStaticFieldGet(Field field);

    public abstract boolean permitsStaticFieldSet(Field field, Object value);
}
