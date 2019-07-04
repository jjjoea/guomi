package cn.ming.crypto;

import java.io.IOException;

public class TestSM4 {
	public static void main(String[] args) throws IOException 
	{
		String plainText = "abcd";
		
		SM4Utils sm4 = new SM4Utils();
		sm4.secretKey = "JeF8U9wHFOMfs2Y8";
		sm4.hexString = false;
		
		System.out.println("ECB model");
		String cipherText = sm4.encryptData_ECB(plainText);
		System.out.println("ciphertext: " + cipherText);
		System.out.println("");
		
		plainText = sm4.decryptData_ECB(cipherText);
		System.out.println("plaintext: " + plainText);
		System.out.println("");
		
		System.out.println("CBC model");
		sm4.iv = "UISwD9fW6cFh9SNS";
		cipherText = sm4.encryptData_CBC(plainText);
		System.out.println("ciphertext: " + cipherText);
		System.out.println("");
		
		plainText = sm4.decryptData_CBC(cipherText);
		System.out.println("plaintext: " + plainText);
	}
}
