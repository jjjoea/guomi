package cn.ming.crypto;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

import cn.ming.crypto.SM2.*;

public class TestUserA {
	private final static Logger logger = Logger.getLogger(TestUserA.class.getName());

	public static void main(String[] args) throws Exception {

		SM2 sm02 = new SM2();

		System.out.println("-----------------用户A  密钥协商-----------------");
		String aID = "ALICE123@YAHOO.COM";

		SM2KeyPair aKeyPair = sm02.generateKeyPair();
		KeyExchange aKeyExchange = new KeyExchange(aID, aKeyPair);
		TransportEntity entity1 = aKeyExchange.keyExchange_1();

		Socket socket = null;
		ObjectOutputStream os = null;
		ObjectInputStream is = null;
		try {
			socket = new Socket("localhost", 10800);
			System.out.println("A-->B 连接成功");

			os = new ObjectOutputStream(socket.getOutputStream());

			os.writeObject(entity1);
			System.out.println("A-->B 发送消息RA");
			os.flush();

			is = new ObjectInputStream(new BufferedInputStream(socket.getInputStream()));
			Object obj = is.readObject();
			if (obj != null) {
				TransportEntity entity2 = (TransportEntity) obj;
				System.out.println("B-->A 收到消息RB、SB，用于计算并确认密钥");
				System.out.println("R点"+entity2.R);
				
				System.out.println("公钥K:"+entity2.K);
				System.out.println("验证S:"+entity2.S);
				System.out.println("用户标识Z:"+entity2.Z);
				TransportEntity entity3 = aKeyExchange.keyExchange_3(entity2);
				os.writeObject(entity3);
				os.flush();
				System.out.println("A-->B 发送消息SA，让B确认密钥");
			}

		} catch (IOException ex) {
			logger.log(Level.SEVERE, null, ex);
		} finally {
			try {
				is.close();
			} catch (Exception ex) {
			}
			try {
				os.close();
			} catch (Exception ex) {
			}
			try {
				socket.close();
			} catch (Exception ex) {
			}
		}

	}

}
