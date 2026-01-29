/*
 * The Alluxio Open Foundation licenses this work under the Apache License, version 2.0
 * (the "License"). You may not use this work except in compliance with the License, which is
 * available at www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied, as more fully set forth in the License.
 *
 * See the NOTICE file distributed with this work for information regarding copyright ownership.
 */

package alluxio.util;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SM4;

/**
 * Sm4 encrypt utilities shared by all components in Alluxio.
 */
public class Sm4Utils {
  private SM4 mSm4;

  /**
   * random secret key.
   */
  public Sm4Utils() {
    this(null);
  }

  /**
   * specific secret key.
   *
   * @param secretKey secret key
   */
  public Sm4Utils(String secretKey) {
    if (secretKey == null || secretKey.isEmpty()) {
      mSm4 = SmUtil.sm4();
    } else {
      mSm4 = SmUtil.sm4(Base64.decode(secretKey));
    }
  }

  /**
   * get secret key.
   *
   * @return secret key
   */
  public String getSecretKey() {
    return Base64.encode(mSm4.getSecretKey().getEncoded());
  }

  /**
   * encrypt.
   *
   * @param str plaintext string
   * @return encrypt string
   */
  public String encrypt(String str) {
    return mSm4.encryptHex(str);
  }

  /**
   * decrypt.
   * @param encryptStr encrypt string
   * @return plaintext string
   */
  public String decrypt(String encryptStr) {
    return mSm4.decryptStr(encryptStr, CharsetUtil.CHARSET_UTF_8);
  }
}
