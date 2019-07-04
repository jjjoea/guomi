package cn.ming.crypto;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

import cn.ming.crypto.SM2.Signature;

public class TestSign {

	public static void main(String[] args) {

		SM2 sm02 = new SM2();
		System.out.println("-----------------签名与验签------------------");

		SM2KeyPair KeyPair = sm02.generateKeyPair();
		ECPoint pubKey = KeyPair.getPublicKey();
		BigInteger privKey = KeyPair.getPrivateKey();
		/* 也可以从文件导入密钥对 */
		// ECPoint pubKey = sm02.importPublicKey("publickey.pem");
		// BigInteger privKey = sm02.importPrivateKey("privatekey.pem");
		System.out.println("公钥:\n" + pubKey);
		System.out.println("私钥:\n" + privKey.toString(16));

		String IDA = "hanming";
		String M = "Hello World";
		System.out.println("要签名的信息为：" + M);

		Signature signature = sm02.sign(M, IDA, new SM2KeyPair(pubKey, privKey));
		System.out.println("用户标识:" + IDA);
		System.out.println("签名信息:" + M);
		System.out.println("数字签名:" + signature);
		System.out.println("验证签名:" + sm02.verify(M, signature, IDA, pubKey));
	}
}
