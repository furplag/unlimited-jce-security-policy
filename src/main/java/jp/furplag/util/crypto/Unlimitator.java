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

import java.io.OutputStream;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Security;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.StreamHandler;

import jp.furplag.reflect.SavageReflection;

/**
 * turn "isRestricted" off JCE security policy .
 *
 * <h1>This is now no longer needed for Java 9, nor for any recent release of Java 6, 7, or 8.</h1>
 *
 * @author furplag
 * @see <a href="https://bugs.openjdk.java.net/browse/JDK-8170157">https://bugs.openjdk.java.net/browse/JDK-8170157</a>
 */
public final class Unlimitator {

  /** logging */
  private static final class InstantiveStreamHandler extends StreamHandler {
    private InstantiveStreamHandler(OutputStream out) {
      setOutputStream(out);
    }
  }

  public Unlimitator() {
    try {
      unchainRestriction();
    } catch (Exception e) {
      Logger logger = Logger.getGlobal();
      logger.setUseParentHandlers(false);
      logger.addHandler(new InstantiveStreamHandler(System.out));
      logger.log(Level.WARNING, "Failed to remove cryptography restrictions .", e);
    }
  }

  private static void unchainRestriction() throws ReflectiveOperationException, SecurityException {
    if (isUnderLimitation(Boolean.valueOf(Objects.toString(SavageReflection.get(Class.forName("javax.crypto.JceSecurity"), "isRestricted"), "false")))) {
      removeRestriction();
    }
    unlimitation();
  }

  /**
   * remove restriction from Java Crypto Extension .
   *
   * @throws ReflectiveOperationException
   * @throws SecurityException
   */
  private static void removeRestriction() throws ReflectiveOperationException, SecurityException {
    Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
    SavageReflection.set(jceSecurity, "isRestricted", false);
    ((Map<?, ?>) SavageReflection.get(SavageReflection.get(jceSecurity, "defaultPolicy"), "perms")).clear();
    ((PermissionCollection) SavageReflection.get(jceSecurity, "defaultPolicy")).add(((Permission) SavageReflection.get(Class.forName("javax.crypto.CryptoAllPermission"), "INSTANCE")));
  }

  private static void unlimitation() {
    if (!"unlimited".equals(Security.getProperty("crypto.policy"))) Security.setProperty("crypto.policy", "unlimited");
  }

  private static boolean isUnderLimitation(final boolean isRestricted) {
    return isRestricted && isLimitedableRuntime() && isLimitedableVersion();
  }

  private static boolean isLimitedableRuntime() {
    return "Java(TM) SE Runtime Environment".equals(System.getProperty("java.runtime.name"));
  }

  private static boolean isLimitedableVersion() {
    return
      Objects.toString(System.getProperty("java.vm.specification.version")).startsWith("1") &&
      "1.8.0_151".compareTo(Objects.toString(System.getProperty("java.version"))) > 0;
  }
}
