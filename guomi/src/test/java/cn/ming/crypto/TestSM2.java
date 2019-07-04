package cn.ming.crypto;

import org.bouncycastle.math.ec.ECPoint;

import cn.ming.crypto.SM2;
import cn.ming.crypto.SM2KeyPair;

import java.math.BigInteger;

public class TestSM2 {

	public static void main(String[] args) {
		SM2 sm02 = new SM2();
		//SM2KeyPair keys = sm02.generateKeyPair();
		//ECPoint pubKey = keys.getPublicKey();
		//BigInteger privKey = keys.getPrivateKey();
		/* 也可以从文件导入密钥对 */
		ECPoint pubKey = sm02.importPublicKey("publickey.pem");
		BigInteger privKey = sm02.importPrivateKey("privatekey.pem");

		System.out.println("公钥:\n" + pubKey.toString());
		System.out.println("私钥:\n" + privKey.toString(16));

		String plaintext = "";
		System.out.println("明文:\n" + plaintext);

		/* 加密 */
		byte[] data = sm02.encrypt(plaintext, pubKey);
		//System.out.println(data.toString());
		System.out.println("密文:");
		
		SM2.printHexString(data);
		String data1;
		data1 = SM2.getHexString(data);
		System.out.println(data1);
		// System.out.println("encrypt: " + data);

		/* 解密 */
		String origin = sm02.decrypt(data, privKey);
		System.out.println("解密后明文:");
		System.out.println(origin);
	}
}
