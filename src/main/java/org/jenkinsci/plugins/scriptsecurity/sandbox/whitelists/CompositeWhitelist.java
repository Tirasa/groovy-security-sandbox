/*
 * Copyright (C) 2007-2025 Crafter Software Corporation. All Rights Reserved.
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

import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

/**
 * Composite of multiple whitelists
 * A call is permitted if all delegates permit it
 */
public class CompositeWhitelist extends Whitelist {

    protected final Collection<? extends Whitelist> delegates;

    public CompositeWhitelist(final Collection<? extends Whitelist> delegates) {
        if (delegates == null || delegates.isEmpty()) {
            throw new IllegalArgumentException("delegates must not be empty");
        }
        if (delegates.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("delegates must not contain null elements");
        }
        this.delegates = Collections.unmodifiableCollection(delegates);
    }

    @Override
    public boolean permitsMethod(final Method method, final Object receiver, final Object[] args) {
        return delegates.stream().allMatch(delegate -> delegate.permitsMethod(method, receiver, args));
    }

    @Override
    public boolean permitsConstructor(final Constructor<?> constructor, final Object[] args) {
        return delegates.stream().allMatch(delegate -> delegate.permitsConstructor(constructor, args));
    }

    @Override
    public boolean permitsStaticMethod(final Method method, final Object[] args) {
        return delegates.stream().allMatch(delegate -> delegate.permitsStaticMethod(method, args));
    }

    @Override
    public boolean permitsFieldGet(final Field field, final Object receiver) {
        return delegates.stream().allMatch(delegate -> delegate.permitsFieldGet(field, receiver));
    }

    @Override
    public boolean permitsFieldSet(final Field field, final Object receiver, final Object value) {
        return delegates.stream().allMatch(delegate -> delegate.permitsFieldSet(field, receiver, value));
    }

    @Override
    public boolean permitsStaticFieldGet(final Field field) {
        return delegates.stream().allMatch(delegate -> delegate.permitsStaticFieldGet(field));
    }

    @Override
    public boolean permitsStaticFieldSet(final Field field, final Object value) {
        return delegates.stream().allMatch(delegate -> delegate.permitsStaticFieldSet(field, value));
    }

    @Override
    public boolean isAllowedGetEnvSystemMethod(final Method m, final Object[] args) {
        return delegates.stream().allMatch(delegate -> delegate.isAllowedGetEnvSystemMethod(m, args));
    }
}
