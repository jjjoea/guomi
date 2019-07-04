package cn.ming.crypto;

import java.awt.Window.Type;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * SM2公钥加密算法实现 包括 -签名,验签 -密钥交换 -公钥加密,私钥解密
 * 
 *
 */
public class SM2TestParams {

	/* SM2椭圆曲线公钥密码算法推荐曲线参数*/
	private static BigInteger n = new BigInteger(
			"8542D69E" + "4C044F18" + "E8B92435" + "BF6FF7DD" + "29772063" + "0485628D" + "5AE74EE7" + "C32E79B7", 16);

	private static BigInteger p = new BigInteger(
			"8542D69E" + "4C044F18" + "E8B92435" + "BF6FF7DE" + "45728391" + "5C45517D" + "722EDB8B" + "08F1DFC3", 16);
	       
	private static BigInteger a = new BigInteger(
			"787968B4" + "FA32C3FD" + "2417842E" + "73BBFEFF" + "2F3C848B" + "6831D7E0" + "EC65228B" + "3937E498", 16);

	private static BigInteger b = new BigInteger(
			"63E4C6D3" + "B23B0C84" + "9CF84241" + "484BFE48" + "F61D59A5" + "B16BA06E" + "6E12D1DA" + "27C5249A", 16);

	private static BigInteger gx = new BigInteger(
			"421DEBD6" + "1B62EAB6" + "746434EB" + "C3CC315E" + "32220B3B" + "ADD50BDC" + "4C4E6C14" + "7FEDD43D", 16);

	private static BigInteger gy = new BigInteger(
			"0680512B" + "CBB42C07" + "D47349D2" + "153B70C4" + "E5D7FDFC" + "BFA36EA1" + "A85841B9" + "E46E09A2", 16);
	
	//BigInteger [] big = new BigInteger()[6];
	//BigInteger[] arr={new BigInteger("259695496911122585"),new BigInteger("420196140727489673")};


	//big[1]=a;
	//System.out.println(arr[1]);

	private static ECDomainParameters ecc_bc_spec;
	private static int w = (int) Math.ceil(n.bitLength() * 1.0 / 2) - 1;
	private static BigInteger _2w = new BigInteger("2").pow(w);
	private static final int DIGEST_LENGTH = 32;

	private static SecureRandom random = new SecureRandom();
	private static ECCurve.Fp curve;
	private static ECPoint G;
	private boolean debug = false;

	public boolean isDebug() {
		return debug;
	}

	public void setDebug(boolean debug) {
		this.debug = debug;
	}

	/**
	 * 以16进制打印字节数组
	 * 
	 * @param b
	 */
	public static void printHexString(byte[] b) {
		for (int i = 0; i < b.length; i++) {
			String hex = Integer.toHexString(b[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			System.out.print(hex.toUpperCase()+" ");
		}
		System.out.println();
	}

	/**
	 * 随机数生成器
	 * 
	 * @param max
	 * @return
	 */
	private static BigInteger random(BigInteger max) {

		BigInteger r = new BigInteger(256, random);
		// int count = 1;

		while (r.compareTo(max) >= 0) {
			r = new BigInteger(128, random);
			// count++;
		}

		// System.out.println("count: " + count);
		return r;
	}

	/**
	 * 判断字节数组是否全0
	 * 
	 * @param buffer
	 * @return
	 */
	private boolean allZero(byte[] buffer) {
		for (int i = 0; i < buffer.length; i++) {
			if (buffer[i] != 0)
				return false;
		}
		return true;
	}

	/**
	 * 公钥加密
	 * 
	 * @param input     加密原文
	 * @param publicKey 公钥
	 * @return
	 */
	public byte[] encrypt(String input, ECPoint publicKey) {

		byte[] inputBuffer = input.getBytes();
		System.out.println("明文16进制:");
		printHexString(inputBuffer);
		if (debug)
			printHexString(inputBuffer);

		byte[] C1Buffer;
		ECPoint kpb;
		byte[] t;
		do {
			/* 1 产生随机数k，k属于[1, n-1] */
			//BigInteger k = random(n);
			BigInteger k = new BigInteger(
					"4C62EEFD" + "6ECFC2B9" + "5B92FD6C" + "3D957514" + "8AFA1742" + "5546D490" + "18E5388D" + "49DD7B4F", 16);
			if (debug) {
				System.out.print("k: ");
				printHexString(k.toByteArray());
			}

			/* 2 计算椭圆曲线点C1 = [k]G = (x1, y1) */
			ECPoint C1 = G.multiply(k);
			C1Buffer = C1.getEncoded(false);
			if (debug) {
				System.out.print("C1: ");
				printHexString(C1Buffer);
			}

			/*
			 * 3 计算椭圆曲线点 S = [h]Pb
			 */
			BigInteger h = ecc_bc_spec.getH();
			if (h != null) {
				ECPoint S = publicKey.multiply(h);
				if (S.isInfinity())
					throw new IllegalStateException();
			}

			/* 4 计算 [k]PB = (x2, y2) */
			kpb = publicKey.multiply(k).normalize();

			/* 5 计算 t = KDF(x2||y2, klen) */
			byte[] kpbBytes = kpb.getEncoded(false);
			t = KDF(kpbBytes, inputBuffer.length);
			// DerivationFunction kdf = new KDF1BytesGenerator(new
			// ShortenedDigest(new SHA256Digest(), DIGEST_LENGTH));
			//
			// t = new byte[inputBuffer.length];
			// kdf.init(new ISO18033KDFParameters(kpbBytes));
			// kdf.generateBytes(t, 0, t.length);
		} while (allZero(t));

		/* 6 计算C2=M^t */
		byte[] C2 = new byte[inputBuffer.length];
		for (int i = 0; i < inputBuffer.length; i++) {
			C2[i] = (byte) (inputBuffer[i] ^ t[i]);
		}

		/* 7 计算C3 = Hash(x2 || M || y2) */
		byte[] C3 = sm3hash(kpb.getXCoord().toBigInteger().toByteArray(), inputBuffer,
				kpb.getYCoord().toBigInteger().toByteArray());

		/* 8 输出密文 C=C1 || C2 || C3 */

		byte[] encryptResult = new byte[C1Buffer.length + C2.length + C3.length];

		System.arraycopy(C1Buffer, 0, encryptResult, 0, C1Buffer.length);
		System.arraycopy(C2, 0, encryptResult, C1Buffer.length, C2.length);
		System.arraycopy(C3, 0, encryptResult, C1Buffer.length + C2.length, C3.length);

		if (debug) {
			System.out.print("密文: ");
			printHexString(encryptResult);
		}

		return encryptResult;
	}

	/**
	 * 私钥解密
	 * 
	 * @param encryptData 密文数据字节数组
	 * @param privateKey  解密私钥
	 * @return
	 */
	public String decrypt(byte[] encryptData, BigInteger privateKey) {

		if (debug)
			System.out.println("encryptData length: " + encryptData.length);

		byte[] C1Byte = new byte[65];
		System.arraycopy(encryptData, 0, C1Byte, 0, C1Byte.length);

		ECPoint C1 = curve.decodePoint(C1Byte).normalize();

		/*
		 * 计算椭圆曲线点 S = [h]C1 是否为无穷点
		 */
		BigInteger h = ecc_bc_spec.getH();
		if (h != null) {
			ECPoint S = C1.multiply(h);
			if (S.isInfinity())
				throw new IllegalStateException();
		}
		/* 计算[dB]C1 = (x2, y2) */
		ECPoint dBC1 = C1.multiply(privateKey).normalize();

		/* 计算t = KDF(x2 || y2, klen) */
		byte[] dBC1Bytes = dBC1.getEncoded(false);
		int klen = encryptData.length - 65 - DIGEST_LENGTH;
		byte[] t = KDF(dBC1Bytes, klen);
		// DerivationFunction kdf = new KDF1BytesGenerator(new
		// ShortenedDigest(new SHA256Digest(), DIGEST_LENGTH));
		// if (debug)
		// System.out.println("klen = " + klen);
		// kdf.init(new ISO18033KDFParameters(dBC1Bytes));
		// kdf.generateBytes(t, 0, t.length);

		if (allZero(t)) {
			System.err.println("all zero");
			throw new IllegalStateException();
		}

		/* 5 计算M'=C2^t */
		byte[] M = new byte[klen];
		for (int i = 0; i < M.length; i++) {
			M[i] = (byte) (encryptData[C1Byte.length + i] ^ t[i]);
		}
		if (debug)
			printHexString(M);

		/* 6 计算 u = Hash(x2 || M' || y2) 判断 u == C3是否成立 */
		byte[] C3 = new byte[DIGEST_LENGTH];

		if (debug)
			try {
				System.out.println("M = " + new String(M, "UTF8"));
			} catch (UnsupportedEncodingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

		System.arraycopy(encryptData, encryptData.length - DIGEST_LENGTH, C3, 0, DIGEST_LENGTH);
		byte[] u = sm3hash(dBC1.getXCoord().toBigInteger().toByteArray(), M,
				dBC1.getYCoord().toBigInteger().toByteArray());
		if (Arrays.equals(u, C3)) {
			if (debug)
				System.out.println("解密成功");
			try {
				return new String(M, "UTF8");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			return null;
		} else {
			if (debug) {
				System.out.print("u = ");
				printHexString(u);
				System.out.print("C3 = ");
				printHexString(C3);
				System.err.println("解密验证失败");
			}
			return null;
		}

	}

	// /**
	// * SHA摘要
	// * @param x2
	// * @param M
	// * @param y2
	// * @return
	// */
	// private byte[] calculateHash(BigInteger x2, byte[] M, BigInteger y2) {
	// ShortenedDigest digest = new ShortenedDigest(new SHA256Digest(),
	// DIGEST_LENGTH);
	// byte[] buf = x2.toByteArray();
	// digest.update(buf, 0, buf.length);
	// digest.update(M, 0, M.length);
	// buf = y2.toByteArray();
	// digest.update(buf, 0, buf.length);
	//
	// buf = new byte[DIGEST_LENGTH];
	// digest.doFinal(buf, 0);
	//
	// return buf;
	// }

	/**
	 * 判断是否在范围内
	 * 
	 * @param param
	 * @param min
	 * @param max
	 * @return
	 */
	private boolean between(BigInteger param, BigInteger min, BigInteger max) {
		if (param.compareTo(min) >= 0 && param.compareTo(max) < 0) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * 判断生成的公钥是否合法
	 * 
	 * @param publicKey
	 * @return
	 */
	private boolean checkPublicKey(ECPoint publicKey) {

		if (!publicKey.isInfinity()) {

			BigInteger x = publicKey.getXCoord().toBigInteger();
			BigInteger y = publicKey.getYCoord().toBigInteger();

			if (between(x, new BigInteger("0"), p) && between(y, new BigInteger("0"), p)) {

				BigInteger xResult = x.pow(3).add(a.multiply(x)).add(b).mod(p);

				if (debug)
					System.out.println("xResult: " + xResult.toString());

				BigInteger yResult = y.pow(2).mod(p);

				if (debug)
					System.out.println("yResult: " + yResult.toString());

				if (yResult.equals(xResult) && publicKey.multiply(n).isInfinity()) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * 生成密钥对
	 * 
	 * @return
	 */
	public SM2KeyPair generateKeyPairEncrypt() {

		//BigInteger d = random(n.subtract(new BigInteger("1")));

		BigInteger d = new BigInteger(
				"1649AB77" + "A00637BD" + "5E2EFE28" + "3FBF3535" + "34AA7F7C" + "B89463F2" + "08DDBC29" + "20BB0DA0", 16);


		SM2KeyPair keyPair = new SM2KeyPair(G.multiply(d).normalize(), d);

		if (checkPublicKey(keyPair.getPublicKey())) {
			if (debug)
				System.out.println("generate key successfully");
			return keyPair;
		} else {
			if (debug)
				System.err.println("generate key failed");
			return null;
		}
	}

	/**
	 * 生成密钥对
	 * 
	 * @return
	 */
	public SM2KeyPair generateKeyPairSign() {

		//BigInteger d = random(n.subtract(new BigInteger("1")));

		BigInteger d = new BigInteger(
				"128B2FA8 BD433C6C 068C8D80 3DFF7979 2A519A55 171B1B65 0C23661D 15897263".replace(" ", ""), 16);

		SM2KeyPair keyPair = new SM2KeyPair(G.multiply(d).normalize(), d);

		if (checkPublicKey(keyPair.getPublicKey())) {
			if (debug)
				System.out.println("generate key successfully");
			return keyPair;
		} else {
			if (debug)
				System.err.println("generate key failed");
			return null;
		}
	}
	
	/**
	 * 生成密钥对
	 * 
	 * @return
	 */
	public SM2KeyPair generateKeyPairA() {

		//BigInteger d = random(n.subtract(new BigInteger("1")));

		BigInteger d = new BigInteger(
				"6FCBA2EF 9AE0AB90 2BC3BDE3 FF915D44 BA4CC78F 88E2F8E7 F8996D3B 8CCEEDEE".replace(" ", ""), 16);
		

		SM2KeyPair keyPair = new SM2KeyPair(G.multiply(d).normalize(), d);

		if (checkPublicKey(keyPair.getPublicKey())) {
			if (debug)
				System.out.println("generate key successfully");
			return keyPair;
		} else {
			if (debug)
				System.err.println("generate key failed");
			return null;
		}
	}
	
	/**
	 * 生成密钥对
	 * 
	 * @return
	 */
	public SM2KeyPair generateKeyPairB() {

		//BigInteger d = random(n.subtract(new BigInteger("1")));

		BigInteger d = new BigInteger(
				"5E35D7D3 F3C54DBA C72E6181 9E730B01 9A84208C A3A35E4C 2E353DFC CB2A3B53".replace(" ", ""), 16);

		SM2KeyPair keyPair = new SM2KeyPair(G.multiply(d).normalize(), d);

		if (checkPublicKey(keyPair.getPublicKey())) {
			if (debug)
				System.out.println("generate key successfully");
			return keyPair;
		} else {
			if (debug)
				System.err.println("generate key failed");
			return null;
		}
	}
	
	public SM2TestParams() {
		curve = new ECCurve.Fp(p, // q
				a, // a
				b); // b
		G = curve.createPoint(gx, gy);
		ecc_bc_spec = new ECDomainParameters(curve, G, n);
		//BigInteger[] arr={n,p,a,b};
		//System.out.println("=============:\n" + arr[0].toString(16));
		
	}

	public SM2TestParams(boolean debug) {
		this();
		this.debug = debug;
	}

	/**
	 * 导出公钥到本地
	 * 
	 * @param publicKey
	 * @param path
	 */
	public void exportPublicKey(ECPoint publicKey, String path) {
		File file = new File(path);
		try {
			if (!file.exists())
				file.createNewFile();
			byte buffer[] = publicKey.getEncoded(false);
			FileOutputStream fos = new FileOutputStream(file);
			fos.write(buffer);
			fos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 从本地导入公钥
	 * 
	 * @param path
	 * @return
	 */
	public ECPoint importPublicKey(String path) {
		File file = new File(path);
		try {
			if (!file.exists())
				return null;
			FileInputStream fis = new FileInputStream(file);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();

			byte buffer[] = new byte[16];
			int size;
			while ((size = fis.read(buffer)) != -1) {
				baos.write(buffer, 0, size);
			}
			fis.close();
			return curve.decodePoint(baos.toByteArray());
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 导出私钥到本地
	 * 
	 * @param privateKey
	 * @param path
	 */
	public void exportPrivateKey(BigInteger privateKey, String path) {
		File file = new File(path);
		try {
			if (!file.exists())
				file.createNewFile();
			ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(file));
			oos.writeObject(privateKey);
			oos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 从本地导入私钥
	 * 
	 * @param path
	 * @return
	 */
	public BigInteger importPrivateKey(String path) {
		File file = new File(path);
		try {
			if (!file.exists())
				return null;
			FileInputStream fis = new FileInputStream(file);
			ObjectInputStream ois = new ObjectInputStream(fis);
			BigInteger res = (BigInteger) (ois.readObject());
			ois.close();
			fis.close();
			return res;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 字节数组拼接
	 * 
	 * @param params
	 * @return
	 */
	private static byte[] join(byte[]... params) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] res = null;
		try {
			for (int i = 0; i < params.length; i++) {
				baos.write(params[i]);
			}
			res = baos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return res;
	}

	/**
	 * sm3摘要
	 * 
	 * @param params
	 * @return
	 */
	private static byte[] sm3hash(byte[]... params) {
		byte[] res = null;
		try {
			res = SM3.hash(join(params));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return res;
	}

	/**
	 * 取得用户标识字节数组
	 * 
	 * @param IDA
	 * @param aPublicKey
	 * @return
	 */
	private static byte[] ZA(String IDA, ECPoint aPublicKey) {
		byte[] idaBytes = IDA.getBytes();
		int entlenA = idaBytes.length * 8;
		byte[] ENTLA = new byte[] { (byte) (entlenA & 0xFF00), (byte) (entlenA & 0x00FF) };
		byte[] ZA = sm3hash(ENTLA, idaBytes, a.toByteArray(), b.toByteArray(), gx.toByteArray(), gy.toByteArray(),
				aPublicKey.getXCoord().toBigInteger().toByteArray(),
				aPublicKey.getYCoord().toBigInteger().toByteArray());
		return ZA;
	}

	/**
	 * 签名
	 * 
	 * @param M       签名信息
	 * @param IDA     签名方唯一标识
	 * @param keyPair 签名方密钥对
	 * @return 签名
	 */
	public Signature sign(String M, String IDA, SM2KeyPair keyPair) {
		byte[] ZA = ZA(IDA, keyPair.getPublicKey());
		byte[] M_ = join(ZA, M.getBytes());
		BigInteger e = new BigInteger(1, sm3hash(M_));
		BigInteger k = new BigInteger(
		"6CB28D99 385C175C 94F94E93 4817663F C176D925 DD72B727 260DBAAE 1FB2F96F".replace(" ", ""), 16);
		//BigInteger k;
		BigInteger r;
		do {
			//k = random(n);
			ECPoint p1 = G.multiply(k).normalize();
			BigInteger x1 = p1.getXCoord().toBigInteger();
			r = e.add(x1);
			r = r.mod(n);
		} while (r.equals(BigInteger.ZERO) || r.add(k).equals(n));

		BigInteger s = ((keyPair.getPrivateKey().add(BigInteger.ONE).modInverse(n))
				.multiply((k.subtract(r.multiply(keyPair.getPrivateKey()))).mod(n))).mod(n);

		return new Signature(r, s);
	}

	/**
	 * 验签
	 * 
	 * @param M          签名信息
	 * @param signature  签名
	 * @param IDA        签名方唯一标识
	 * @param aPublicKey 签名方公钥
	 * @return true or false
	 */
	public boolean verify(String M, Signature signature, String IDA, ECPoint aPublicKey) {
		if (!between(signature.r, BigInteger.ONE, n))
			return false;
		if (!between(signature.s, BigInteger.ONE, n))
			return false;

		byte[] M_ = join(ZA(IDA, aPublicKey), M.getBytes());
		BigInteger e = new BigInteger(1, sm3hash(M_));
		BigInteger t = signature.r.add(signature.s).mod(n);

		if (t.equals(BigInteger.ZERO))
			return false;

		ECPoint p1 = G.multiply(signature.s).normalize();
		ECPoint p2 = aPublicKey.multiply(t).normalize();
		BigInteger x1 = p1.add(p2).normalize().getXCoord().toBigInteger();
		BigInteger R = e.add(x1).mod(n);
		if (R.equals(signature.r))
			return true;
		return false;
	}

	/**
	 * 密钥派生函数
	 * 
	 * @param Z
	 * @param klen 生成klen字节数长度的密钥
	 * @return
	 */
	private static byte[] KDF(byte[] Z, int klen) {
		int ct = 1;
		int end = (int) Math.ceil(klen * 1.0 / 32);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			for (int i = 1; i < end; i++) {
				baos.write(sm3hash(Z, SM3.toByteArray(ct)));
				ct++;
			}
			byte[] last = sm3hash(Z, SM3.toByteArray(ct));
			//若klen/v是整数，
			if (klen % 32 == 0) {
				baos.write(last);
			} else
				// 写入向下取整
				baos.write(last, 0, klen % 32);
			return baos.toByteArray();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 传输实体类
	 * 
	 *
	 */
	public static class TransportEntity implements Serializable {
		final byte[] R; // R点
		final byte[] S; // 验证S
		final byte[] Z; // 用户标识
		final byte[] K; // 公钥

		public TransportEntity(byte[] r, byte[] s, byte[] z, ECPoint pKey) {
			R = r;
			S = s;
			Z = z;
			K = pKey.getEncoded(false);
		}
	}

	/**
	 * 密钥协商辅助类
	 * 
	 * 
	 */
	public static class KeyExchange {
		BigInteger rA;
		ECPoint RA;
		ECPoint V;
		byte[] Z;
		byte[] key;

		String ID;
		SM2KeyPair keyPair;

		public KeyExchange(String ID, SM2KeyPair keyPair) {
			this.ID = ID;
			this.keyPair = keyPair;
			this.Z = ZA(ID, keyPair.getPublicKey());
		}

		/**
		 * 密钥协商发起第一步
		 * 
		 * @return
		 */
		public TransportEntity keyExchange_1() {
			//rA = random(n);
			rA=new BigInteger("83A2C9C8 B96E5AF7 0BD480B4 72409A9A 327257F1 EBB73F5B 073354B2 48668563".replace(" ", ""),16);
			RA = G.multiply(rA).normalize();
			return new TransportEntity(RA.getEncoded(false), null, Z, keyPair.getPublicKey());
		}

		/**
		 * 密钥协商响应方
		 * 
		 * @param entity 传输实体
		 * @return
		 */
		public TransportEntity keyExchange_2(TransportEntity entity) {
			//BigInteger rB = random(n);
			BigInteger rB=new BigInteger("33FE2194 0342161C 55619C4A 0C060293 D543C80A F19748CE 176D8347 7DE71C80".replace(" ", ""),16);
			ECPoint RB = G.multiply(rB).normalize();

			this.rA = rB;
			this.RA = RB;

			BigInteger x2 = RB.getXCoord().toBigInteger();
			x2 = _2w.add(x2.and(_2w.subtract(BigInteger.ONE)));

			BigInteger tB = keyPair.getPrivateKey().add(x2.multiply(rB)).mod(n);
			ECPoint RA = curve.decodePoint(entity.R).normalize();

			BigInteger x1 = RA.getXCoord().toBigInteger();
			x1 = _2w.add(x1.and(_2w.subtract(BigInteger.ONE)));

			ECPoint aPublicKey = curve.decodePoint(entity.K).normalize();
			ECPoint temp = aPublicKey.add(RA.multiply(x1).normalize()).normalize();
			ECPoint V = temp.multiply(ecc_bc_spec.getH().multiply(tB)).normalize();
			if (V.isInfinity())
				throw new IllegalStateException();
			this.V = V;

			byte[] xV = V.getXCoord().toBigInteger().toByteArray();
			byte[] yV = V.getYCoord().toBigInteger().toByteArray();
			byte[] KB = KDF(join(xV, yV, entity.Z, this.Z), 16);
			key = KB;
			System.out.print("协商得B密钥:");
			printHexString(KB);
			byte[] sB = sm3hash(new byte[] { 0x02 }, yV,
					sm3hash(xV, entity.Z, this.Z, RA.getXCoord().toBigInteger().toByteArray(),
							RA.getYCoord().toBigInteger().toByteArray(), RB.getXCoord().toBigInteger().toByteArray(),
							RB.getYCoord().toBigInteger().toByteArray()));
			return new TransportEntity(RB.getEncoded(false), sB, this.Z, keyPair.getPublicKey());
		}

		/**
		 * 密钥协商发起方第二步
		 * 
		 * @param entity 传输实体
		 */
		public TransportEntity keyExchange_3(TransportEntity entity) {
			BigInteger x1 = RA.getXCoord().toBigInteger();
			x1 = _2w.add(x1.and(_2w.subtract(BigInteger.ONE)));

			BigInteger tA = keyPair.getPrivateKey().add(x1.multiply(rA)).mod(n);
			ECPoint RB = curve.decodePoint(entity.R).normalize();

			BigInteger x2 = RB.getXCoord().toBigInteger();
			x2 = _2w.add(x2.and(_2w.subtract(BigInteger.ONE)));

			ECPoint bPublicKey = curve.decodePoint(entity.K).normalize();
			ECPoint temp = bPublicKey.add(RB.multiply(x2).normalize()).normalize();
			ECPoint U = temp.multiply(ecc_bc_spec.getH().multiply(tA)).normalize();
			if (U.isInfinity())
				throw new IllegalStateException();
			this.V = U;

			byte[] xU = U.getXCoord().toBigInteger().toByteArray();
			byte[] yU = U.getYCoord().toBigInteger().toByteArray();
			byte[] KA = KDF(join(xU, yU, this.Z, entity.Z), 16);
			key = KA;
			System.out.print("协商得A密钥:");
			printHexString(KA);
			byte[] s1 = sm3hash(new byte[] { 0x02 }, yU,
					sm3hash(xU, this.Z, entity.Z, RA.getXCoord().toBigInteger().toByteArray(),
							RA.getYCoord().toBigInteger().toByteArray(), RB.getXCoord().toBigInteger().toByteArray(),
							RB.getYCoord().toBigInteger().toByteArray()));
			if (Arrays.equals(entity.S, s1))
				System.out.println("B-->A 密钥确认成功");
			else
				System.out.println("B-->A 密钥确认失败");
			byte[] sA = sm3hash(new byte[] { 0x03 }, yU,
					sm3hash(xU, this.Z, entity.Z, RA.getXCoord().toBigInteger().toByteArray(),
							RA.getYCoord().toBigInteger().toByteArray(), RB.getXCoord().toBigInteger().toByteArray(),
							RB.getYCoord().toBigInteger().toByteArray()));

			return new TransportEntity(RA.getEncoded(false), sA, this.Z, keyPair.getPublicKey());
		}

		/**
		 * 密钥确认最后一步
		 * 
		 * @param entity 传输实体
		 */
		public void keyExchange_4(TransportEntity entity) {
			byte[] xV = V.getXCoord().toBigInteger().toByteArray();
			byte[] yV = V.getYCoord().toBigInteger().toByteArray();
			ECPoint RA = curve.decodePoint(entity.R).normalize();
			byte[] s2 = sm3hash(new byte[] { 0x03 }, yV,
					sm3hash(xV, entity.Z, this.Z, RA.getXCoord().toBigInteger().toByteArray(),
							RA.getYCoord().toBigInteger().toByteArray(),
							this.RA.getXCoord().toBigInteger().toByteArray(),
							this.RA.getYCoord().toBigInteger().toByteArray()));
			if (Arrays.equals(entity.S, s2))
				System.out.println("A-->B 密钥确认成功");
			else
				System.out.println("A-->B 密钥确认失败");
		}
	}

	public static void main(String[] args) throws UnsupportedEncodingException {

		SM2TestParams sm02 = new SM2TestParams();

		System.out.println("-----------------公钥加密与解密算法正确性验证-----------------");
		//ECPoint publicKey = sm02.importPublicKey("publickey.pem");
		//BigInteger privateKey = sm02.importPrivateKey("privatekey.pem");
		
		SM2KeyPair keys = sm02.generateKeyPairEncrypt();
		ECPoint publicKey = keys.getPublicKey();
		BigInteger privateKey = keys.getPrivateKey();
		
		System.out.println("私钥:\n" + privateKey);
		
		System.out.println("公钥:\n"+publicKey);
		
		//printHexString(publicKey.getRawXCoord().getEncoded());
		
		
		byte[] data = sm02.encrypt("encryption standard", publicKey);
		System.out.print("密文:");
		SM2TestParams.printHexString(data);
		System.out.println("解密后明文:" + sm02.decrypt(data, privateKey));

		System.out.println("\n-----------------签名与验签算法正确性验证-----------------");
		String IDA = "ALICE123@YAHOO.COM";
		String M = "message digest";
		
		keys=sm02.generateKeyPairSign();
		publicKey = keys.getPublicKey();
		privateKey = keys.getPrivateKey();
		
		
		Signature signature = sm02.sign(M, IDA, new SM2KeyPair(publicKey, privateKey));
		System.out.println("用户标识:" + IDA);
		System.out.println("签名信息:" + M);
		System.out.println("数字签名:" + signature);
		System.out.println("验证签名:" + sm02.verify(M, signature, IDA, publicKey));

		
		
		
		
		System.out.println("-----------------密钥协商-----------------");
		String aID = "ALICE123@YAHOO.COM";
		SM2KeyPair aKeyPair = sm02.generateKeyPairA();
		KeyExchange aKeyExchange = new KeyExchange(aID, aKeyPair);

		String bID = "BILL456@YAHOO.COM";
		SM2KeyPair bKeyPair = sm02.generateKeyPairB();
		KeyExchange bKeyExchange = new KeyExchange(bID, bKeyPair);
		TransportEntity entity1 = aKeyExchange.keyExchange_1();
		TransportEntity entity2 = bKeyExchange.keyExchange_2(entity1);
		TransportEntity entity3 = aKeyExchange.keyExchange_3(entity2);
		bKeyExchange.keyExchange_4(entity3);
		
		
		
	}

	
	/*
	public static void exchange() {
		SM2TestParams sm02 = new SM2TestParams();

		System.out.println("-----------------密钥协商-----------------");
		String aID = "ALICE123@YAHOO.COM";
		SM2KeyPair aKeyPair = sm02.generateKeyPair();
		KeyExchange aKeyExchange = new KeyExchange(aID, aKeyPair);

		String bID = "BILL456@YAHOO.COM";
		SM2KeyPair bKeyPair = sm02.generateKeyPair();
		KeyExchange bKeyExchange = new KeyExchange(bID, bKeyPair);
		TransportEntity entity1 = aKeyExchange.keyExchange_1();
		TransportEntity entity2 = bKeyExchange.keyExchange_2(entity1);
		TransportEntity entity3 = aKeyExchange.keyExchange_3(entity2);
		bKeyExchange.keyExchange_4(entity3);

	}
	
	*/

	public static class Signature {
		BigInteger r;
		BigInteger s;

		public Signature(BigInteger r, BigInteger s) {
			this.r = r;
			this.s = s;
		}

		public String toString() {
			return r.toString(16) + "," + s.toString(16);
		}
	}
}
