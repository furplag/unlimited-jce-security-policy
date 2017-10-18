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

import static org.junit.Assert.*;

import java.util.Objects;

import org.junit.Test;

import jp.furplag.util.reflect.SavageReflection;

public class UnlimitatorTest {

  @Test
  public void testUnlimitator() throws Exception {
    if (Boolean.valueOf(Objects.toString(SavageReflection.get(null, Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted"))))) {
      new Unlimitator();
      assertFalse(Boolean.valueOf(Objects.toString(SavageReflection.get(null, Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted")))));
      new Unlimitator();
      assertFalse(Boolean.valueOf(Objects.toString(SavageReflection.get(null, Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted")))));

      SavageReflection.set(Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted"), true);
      final String javaRuntimeName = System.getProperty("java.runtime.name");
      System.setProperty("java.runtime.name", "Not a " + javaRuntimeName);
      new Unlimitator();
      System.setProperty("java.runtime.name", javaRuntimeName);
      assertTrue(Boolean.valueOf(Objects.toString(SavageReflection.get(null, Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted")))));

      SavageReflection.set(Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted"), true);
      final String javaVersion = System.getProperty("java.version");
      System.setProperty("java.version", "10" + javaVersion);
      new Unlimitator();
      System.setProperty("java.version", javaVersion);
      assertTrue(Boolean.valueOf(Objects.toString(SavageReflection.get(null, Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted")))));

      new Unlimitator();
      assertFalse(Boolean.valueOf(Objects.toString(SavageReflection.get(null, Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted")))));
    }
  }
}
