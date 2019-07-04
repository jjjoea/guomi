package cn.ming.crypto;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

import cn.ming.crypto.SM2;
import cn.ming.crypto.SM2.KeyExchange;
import cn.ming.crypto.SM2.TransportEntity;

public class TestUserB {
	private final static Logger logger = Logger.getLogger(TestUserB.class.getName());

	public static void main(String[] args) throws Exception {

		SM2 sm02 = new SM2();

		System.out.println("-----------------用户B 密钥协商-----------------");

		String bID = "BILL456@YAHOO.COM";
		SM2KeyPair bKeyPair = sm02.generateKeyPair();
		KeyExchange bKeyExchange = new KeyExchange(bID, bKeyPair);

		ServerSocket server = new ServerSocket(10800);
		Socket socket = server.accept();
		ObjectInputStream is = null;
		ObjectOutputStream os = null;
		try {
			System.out.println("A-->B 连接成功");
			is = new ObjectInputStream(new BufferedInputStream(socket.getInputStream()));
			os = new ObjectOutputStream(socket.getOutputStream());

			Object obj1 = is.readObject();
			if (obj1 != null) {
				TransportEntity entity1 = (TransportEntity) obj1;

				System.out.println("A-->B 收到消息RA，用于计算密钥");
				System.out.println("R点"+entity1.R);
				System.out.println("公钥K:"+entity1.K);
				System.out.println("验证S:"+entity1.S);
				System.out.println("用户标识Z:"+entity1.Z);

				TransportEntity entity2 = bKeyExchange.keyExchange_2(entity1);
				os.writeObject(entity2);
				os.flush();
				System.out.println("B-->A 发送消息RB、SB，让A确认密钥");

				Object obj2 = is.readObject();
				if (obj2 != null) {
					TransportEntity entity3 = (TransportEntity) obj2;
					System.out.println("A-->B 收到消息SA，用于确认密钥");
//					System.out.println("R点"+entity3.R);
//					System.out.println("公钥K:"+entity3.K);
//					System.out.println("验证S:"+entity3.S);
//					System.out.println("用户标识Z:"+entity3.Z);
					bKeyExchange.keyExchange_4(entity3);
				}
			}

		} catch (IOException ex) {
			logger.log(Level.SEVERE, null, ex);
		} catch (ClassNotFoundException ex) {
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
				server.close();
			} catch (Exception ex) {
			}
		}

	}

}
