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

import java.lang.reflect.Field;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.StreamHandler;

import jp.furplag.util.reflect.SavageReflection;

/**
 * turn "isRestricted" off JCE security policy .
 *
 * <h1>This is now no longer needed for Java 9, nor for any recent release of Java 6, 7, or 8.</h1>
 *
 * @author furplag
 * @see <a href="https://bugs.openjdk.java.net/browse/JDK-8170157">https://bugs.openjdk.java.net/browse/JDK-8170157</a>
 */
public final class Unlimitator {

  public Unlimitator() {
    Logger logger = Logger.getGlobal();
    logger.setUseParentHandlers(false);
    logger.addHandler(new StreamHandler() {
      {
        setOutputStream(System.out);
      }
    });
    try {
      unchainRestriction();
    } catch (Exception e) {
      logger.log(Level.SEVERE, "Failed to remove cryptography restrictions .", e);
    }
  }

  /**
   * remove restriction from Java Crypto Extension to using AES more strong key length .
   *
   * @throws ClassNotFoundException
   * @throws NoSuchFieldException
   * @throws SecurityException
   * @throws IllegalArgumentException
   * @throws IllegalAccessException
   */
  private static void unchainRestriction() throws ClassNotFoundException, NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
    Logger logger = Logger.getGlobal();
    logger.setUseParentHandlers(false);
    logger.addHandler(new StreamHandler() {
      {
        setOutputStream(System.out);
      }
    });

    final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
    final Field isRestricted = jceSecurity.getDeclaredField("isRestricted");
    if (!isUnderLimitation() || !Boolean.valueOf(Objects.toString(SavageReflection.get(null, isRestricted), "false"))) {
      return;
    }
    final Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");

    final Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
    final Field perms = cryptoPermissions.getDeclaredField("perms");

    final Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");
    final Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");

    final PermissionCollection defaultPolicy = ((PermissionCollection) SavageReflection.get(null, defaultPolicyField));

    SavageReflection.set(isRestricted, false);
    ((Map<?, ?>) SavageReflection.get(defaultPolicy, perms)).clear();
    defaultPolicy.add(((Permission) SavageReflection.get(null, instance)));
  }

  private static boolean isUnderLimitation() {
    final String javaRuntimeName = System.getProperty("java.runtime.name");
    final String javaVersion = System.getProperty("java.version");

    return "Java(TM) SE Runtime Environment".equals(javaRuntimeName) && (Objects.toString(javaVersion).startsWith("1.7") || Objects.toString(javaVersion).startsWith("1.8"));
  }
}
