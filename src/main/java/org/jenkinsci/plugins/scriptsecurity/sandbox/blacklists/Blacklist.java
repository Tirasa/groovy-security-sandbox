/*
 * Copyright (C) 2007-2022 Crafter Software Corporation. All Rights Reserved.
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
package org.jenkinsci.plugins.scriptsecurity.sandbox.blacklists;

import java.io.IOException;
import java.io.Reader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.StaticWhitelist;

/**
 * Extension of {@link StaticWhitelist} that works as a blacklist by negating all operations
 *
 * @author joseross
 */
public class Blacklist extends StaticWhitelist {

    public Blacklist(final Reader definition) throws IOException {
        super(definition);
    }

    @Override
    public boolean permitsMethod(final Method method, final Object receiver, final Object[] args) {
        return !super.permitsMethod(method, receiver, args);
    }

    @Override
    public boolean permitsConstructor(final Constructor<?> constructor, final Object[] args) {
        return !super.permitsConstructor(constructor, args);
    }

    @Override
    public boolean permitsStaticMethod(final Method method, final Object[] args) {
        return !super.permitsStaticMethod(method, args);
    }

    @Override
    public boolean permitsFieldGet(final Field field, final Object receiver) {
        return !super.permitsFieldGet(field, receiver);
    }

    @Override
    public boolean permitsFieldSet(final Field field, final Object receiver, final Object value) {
        return super.permitsFieldSet(field, receiver, value);
    }

    @Override
    public boolean permitsStaticFieldGet(final Field field) {
        return !super.permitsStaticFieldGet(field);
    }

    @Override
    public boolean permitsStaticFieldSet(final Field field, final Object value) {
        return super.permitsStaticFieldSet(field, value);
    }
}
