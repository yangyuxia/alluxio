package alluxio.util;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SM4;

public class Sm4Utils {
  private SM4 sm4;

  public Sm4Utils() {
    this(null);
  }

  public Sm4Utils(String secretKey) {
    if (secretKey == null || secretKey.isEmpty()) {
      this.sm4 = SmUtil.sm4();
    } else {
      this.sm4 = SmUtil.sm4(Base64.decode(secretKey));
    }
  }

  public String getSecretKey() {
    return Base64.encode(sm4.getSecretKey().getEncoded());
  }

  public String encrypt(String str) {
    return sm4.encryptHex(str);
  }

  public String decrypt(String encryptStr) {
    return sm4.decryptStr(encryptStr, CharsetUtil.CHARSET_UTF_8);
  }
}
