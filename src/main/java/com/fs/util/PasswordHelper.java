package com.fs.util;

import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;
/**
 * 密码加密工具类：
 *
 */
public class PasswordHelper {
	 private static RandomNumberGenerator randomNumberGenerator = new SecureRandomNumberGenerator();  
	public static void encryptPassword(String password, String salt) {
		String salt1 =randomNumberGenerator.nextBytes().toHex();
		System.out.println(salt1);
		String newPassword = new SimpleHash("MD5", password, ByteSource.Util.bytes(salt), 2).toHex();

		System.out.println(newPassword);

	}

	public static void main(String args[]) {
		encryptPassword("123456", "admin8d78869f470951332959580424d4bf4f");
	}
}
