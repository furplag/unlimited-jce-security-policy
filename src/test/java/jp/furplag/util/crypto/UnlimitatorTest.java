/**
 * Copyright (C) 2017+ furplag (https://github.com/furplag)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jp.furplag.util.crypto;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.security.Permission;
import java.security.Security;
import java.util.Objects;

import org.junit.Test;

import jp.furplag.reflect.Reflections;
import jp.furplag.reflect.SavageReflection;

public class UnlimitatorTest {

  private static class TestSecurityManager extends SecurityManager {

    @Override
    public void checkPackageAccess(String pkg) {
      if ("javax.crypto".equals(pkg)) {
        throw new SecurityException();
      }
      super.checkPackageAccess(pkg);
    }

    @Override
    public void checkPermission(Permission perm) {
      return;
    }
  }

  private static void secure() {
    System.setSecurityManager(new TestSecurityManager());
  }

  private static void insecure() {
    System.setSecurityManager(null);
  }

  @Test
  public void testUnlimitator() {
    try {
      secure();
      new Unlimitator();
    } catch (SecurityException e) {
      fail(e.getClass().toString());
    } finally {
      insecure();
    }
    assertThat(new Unlimitator() instanceof Unlimitator, is(true));
  }

  @Test
  public void testIsLimitedableRuntime() throws ReflectiveOperationException {

    String javaRuntimeNameDefault = Objects.toString(System.getProperty("java.runtime.name"));

    System.setProperty("java.runtime.name", "Anonymously Java");
    assertThat(Reflections.findMethod(Unlimitator.class, "isLimitedableRuntime").invoke(null), is(false));
    System.setProperty("java.runtime.name", "java(tm) se runtime environment");
    assertThat(Reflections.findMethod(Unlimitator.class, "isLimitedableRuntime").invoke(null), is(false));
    System.setProperty("java.runtime.name", "Java(TM) SE Runtime Environment");
    assertThat(Reflections.findMethod(Unlimitator.class, "isLimitedableRuntime").invoke(null), is(true));
    System.setProperty("java.runtime.name", javaRuntimeNameDefault);
  }

  @Test
  public void testIsLimitedableVersion() throws ReflectiveOperationException {

    String javaVmSpecificationVersionDefault = Objects.toString(System.getProperty("java.vm.specification.version"));
    String javaVersionDefault = Objects.toString(System.getProperty("java.version"));

    System.setProperty("java.vm.specification.version", "undefined");
    System.setProperty("java.version", "undefined");
    assertThat(Reflections.findMethod(Unlimitator.class, "isLimitedableVersion").invoke(null), is(false));
    System.setProperty("java.vm.specification.version", "1.7");
    System.setProperty("java.version", "1.7.0_80");
    assertThat(Reflections.findMethod(Unlimitator.class, "isLimitedableVersion").invoke(null), is(true));
    System.setProperty("java.vm.specification.version", "1.8");
    System.setProperty("java.version", "1.8.0_150");
    assertThat(Reflections.findMethod(Unlimitator.class, "isLimitedableVersion").invoke(null), is(true));
    System.setProperty("java.vm.specification.version", "1.8");
    System.setProperty("java.version", "1.8.0_151");
    assertThat(Reflections.findMethod(Unlimitator.class, "isLimitedableVersion").invoke(null), is(false));
    System.setProperty("java.vm.specification.version", "1.8");
    System.setProperty("java.version", "1.8.0_152");
    assertThat(Reflections.findMethod(Unlimitator.class, "isLimitedableVersion").invoke(null), is(false));
    System.setProperty("java.vm.specification.version", "9");
    System.setProperty("java.version", "9.0.1");
    assertThat(Reflections.findMethod(Unlimitator.class, "isLimitedableVersion").invoke(null), is(false));
    System.setProperty("java.vm.specification.version", javaVmSpecificationVersionDefault);
    System.setProperty("java.version", javaVersionDefault);
  }

  @Test
  public void testIsUnderLimitation() throws ReflectiveOperationException {
    String javaRuntimeNameDefault = Objects.toString(System.getProperty("java.runtime.name"));
    String javaVmSpecificationVersionDefault = Objects.toString(System.getProperty("java.vm.specification.version"));
    String javaVersionDefault = Objects.toString(System.getProperty("java.version"));

    assertThat(Reflections.findMethod(Unlimitator.class, "isUnderLimitation", boolean.class).invoke(null, false), is(false));

    System.setProperty("java.runtime.name", "Anonymously Java");
    System.setProperty("java.vm.specification.version", "undefined");
    System.setProperty("java.version", "undefined");
    assertThat(Reflections.findMethod(Unlimitator.class, "isUnderLimitation", boolean.class).invoke(null, false), is(false));
    assertThat(Reflections.findMethod(Unlimitator.class, "isUnderLimitation", boolean.class).invoke(null, true), is(false));
    System.setProperty("java.runtime.name", "Java(TM) SE Runtime Environment");
    System.setProperty("java.vm.specification.version", "1.7");
    System.setProperty("java.version", "1.7.0_80");
    assertThat(Reflections.findMethod(Unlimitator.class, "isUnderLimitation", boolean.class).invoke(null, false), is(false));
    assertThat(Reflections.findMethod(Unlimitator.class, "isUnderLimitation", boolean.class).invoke(null, true), is(true));
    System.setProperty("java.vm.specification.version", "1.8");
    System.setProperty("java.version", "1.8.0_150");
    assertThat(Reflections.findMethod(Unlimitator.class, "isUnderLimitation", boolean.class).invoke(null, false), is(false));
    assertThat(Reflections.findMethod(Unlimitator.class, "isUnderLimitation", boolean.class).invoke(null, true), is(true));
    System.setProperty("java.version", "1.8.0_151");
    assertThat(Reflections.findMethod(Unlimitator.class, "isUnderLimitation", boolean.class).invoke(null, false), is(false));
    assertThat(Reflections.findMethod(Unlimitator.class, "isUnderLimitation", boolean.class).invoke(null, true), is(false));
    System.setProperty("java.version", "1.8.0_152");
    assertThat(Reflections.findMethod(Unlimitator.class, "isUnderLimitation", boolean.class).invoke(null, false), is(false));
    assertThat(Reflections.findMethod(Unlimitator.class, "isUnderLimitation", boolean.class).invoke(null, true), is(false));
    System.setProperty("java.vm.specification.version", "9");
    System.setProperty("java.version", "9.0.1");
    assertThat(Reflections.findMethod(Unlimitator.class, "isUnderLimitation", boolean.class).invoke(null, false), is(false));
    assertThat(Reflections.findMethod(Unlimitator.class, "isUnderLimitation", boolean.class).invoke(null, true), is(false));

    System.setProperty("java.runtime.name", javaRuntimeNameDefault);
    System.setProperty("java.vm.specification.version", javaVmSpecificationVersionDefault);
    System.setProperty("java.version", javaVersionDefault);
  }

  @Test
  public void testUnlimitation() throws ReflectiveOperationException {
    String cryptPolicyDefault = Objects.toString(Security.getProperty("crypto.policy"));

    Security.setProperty("crypto.policy", "undefined");
    Reflections.findMethod(Unlimitator.class, "unlimitation").invoke(null);
    assertThat(Security.getProperty("crypto.policy"), is("unlimited"));

    Security.setProperty("crypto.policy", "limited");
    Reflections.findMethod(Unlimitator.class, "unlimitation").invoke(null);
    assertThat(Security.getProperty("crypto.policy"), is("unlimited"));

    Security.setProperty("crypto.policy", "unlimited");
    Reflections.findMethod(Unlimitator.class, "unlimitation").invoke(null);
    assertThat(Security.getProperty("crypto.policy"), is("unlimited"));

    Security.setProperty("crypto.policy", cryptPolicyDefault);
  }

  @Test
  public void testUnchainRestriction() throws ReflectiveOperationException {
    String javaRuntimeNameDefault = Objects.toString(System.getProperty("java.runtime.name"));
    String javaVmSpecificationVersionDefault = Objects.toString(System.getProperty("java.vm.specification.version"));
    String javaVersionDefault = Objects.toString(System.getProperty("java.version"));
    boolean isRestrictedDefault = (boolean) SavageReflection.get(Class.forName("javax.crypto.JceSecurity"), "isRestricted");

    System.setProperty("java.runtime.name", "Java(TM) SE Runtime Environment");
    System.setProperty("java.vm.specification.version", "1.7");
    System.setProperty("java.version", "1.7.0_80");
    SavageReflection.set(Class.forName("javax.crypto.JceSecurity"), "isRestricted", false);
    Reflections.findMethod(Unlimitator.class, "unchainRestriction").invoke(null);
    assertThat(SavageReflection.get(Class.forName("javax.crypto.JceSecurity"), "isRestricted"), is(false));
    SavageReflection.set(Class.forName("javax.crypto.JceSecurity"), "isRestricted", true);
    Reflections.findMethod(Unlimitator.class, "unchainRestriction").invoke(null);
    assertThat(SavageReflection.get(Class.forName("javax.crypto.JceSecurity"), "isRestricted"), is(false));
    System.setProperty("java.vm.specification.version", "1.8");
    System.setProperty("java.version", "1.8.0_150");
    SavageReflection.set(Class.forName("javax.crypto.JceSecurity"), "isRestricted", false);
    Reflections.findMethod(Unlimitator.class, "unchainRestriction").invoke(null);
    assertThat(SavageReflection.get(Class.forName("javax.crypto.JceSecurity"), "isRestricted"), is(false));
    SavageReflection.set(Class.forName("javax.crypto.JceSecurity"), "isRestricted", true);
    Reflections.findMethod(Unlimitator.class, "unchainRestriction").invoke(null);
    assertThat(SavageReflection.get(Class.forName("javax.crypto.JceSecurity"), "isRestricted"), is(false));
    System.setProperty("java.version", "1.8.0_151");
    SavageReflection.set(Class.forName("javax.crypto.JceSecurity"), "isRestricted", false);
    Reflections.findMethod(Unlimitator.class, "unchainRestriction").invoke(null);
    assertThat(SavageReflection.get(Class.forName("javax.crypto.JceSecurity"), "isRestricted"), is(false));
    SavageReflection.set(Class.forName("javax.crypto.JceSecurity"), "isRestricted", true);
    Reflections.findMethod(Unlimitator.class, "unchainRestriction").invoke(null);
    assertThat(SavageReflection.get(Class.forName("javax.crypto.JceSecurity"), "isRestricted"), is(true));
    System.setProperty("java.version", "1.8.0_152");
    SavageReflection.set(Class.forName("javax.crypto.JceSecurity"), "isRestricted", false);
    Reflections.findMethod(Unlimitator.class, "unchainRestriction").invoke(null);
    assertThat(SavageReflection.get(Class.forName("javax.crypto.JceSecurity"), "isRestricted"), is(false));
    SavageReflection.set(Class.forName("javax.crypto.JceSecurity"), "isRestricted", true);
    Reflections.findMethod(Unlimitator.class, "unchainRestriction").invoke(null);
    assertThat(SavageReflection.get(Class.forName("javax.crypto.JceSecurity"), "isRestricted"), is(true));
    System.setProperty("java.vm.specification.version", "9");
    System.setProperty("java.version", "9.0.1");
    SavageReflection.set(Class.forName("javax.crypto.JceSecurity"), "isRestricted", false);
    Reflections.findMethod(Unlimitator.class, "unchainRestriction").invoke(null);
    assertThat(SavageReflection.get(Class.forName("javax.crypto.JceSecurity"), "isRestricted"), is(false));
    SavageReflection.set(Class.forName("javax.crypto.JceSecurity"), "isRestricted", true);
    Reflections.findMethod(Unlimitator.class, "unchainRestriction").invoke(null);
    assertThat(SavageReflection.get(Class.forName("javax.crypto.JceSecurity"), "isRestricted"), is(true));

    System.setProperty("java.runtime.name", javaRuntimeNameDefault);
    System.setProperty("java.vm.specification.version", javaVmSpecificationVersionDefault);
    System.setProperty("java.version", javaVersionDefault);
    SavageReflection.set(Class.forName("javax.crypto.JceSecurity"), "isRestricted", isRestrictedDefault);
  }
}
