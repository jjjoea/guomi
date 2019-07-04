package cn.ming.crypto;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;

import javax.swing.*;

import org.bouncycastle.math.ec.ECPoint;

import cn.ming.crypto.SM2.KeyExchange;
import cn.ming.crypto.SM2.Signature;
import cn.ming.crypto.SM2.TransportEntity;  
public class UI extends JFrame  
{  
    private JTabbedPane tabbedPane;  
    private JLabel label1,label2,label3;  
    private JPanel panel1,panel2,panel3;  
  
    public UI()  
    {  
        super("国密算法小程序"); setSize(450,460);  
  
        Container c = getContentPane();  
        tabbedPane=new JTabbedPane();   //创建选项卡面板对象  
        
        //创建标签  
//        label1=new JLabel("第一个标签的面板",SwingConstants.CENTER); 
//        label2=new JLabel("第二个标签的面板",SwingConstants.CENTER);  
//        label3=new JLabel("第三个标签的面板",SwingConstants.CENTER);  
        label1=new JLabel(); 
        label2=new JLabel();  
        label3=new JLabel();  
        //创建面板  
        panel1=new JPanel();  
        panel2=new JPanel();  
        panel3=new JPanel();  
  
        panel1.add(label1);  
        panel2.add(label2);  
        panel3.add(label3);  
  
//       panel1.setBackground(Color.red);  
//       panel2.setBackground(Color.green);  
//       panel3.setBackground(Color.yellow);
        
        //将标签面板加入到选项卡面板对象上 
        tabbedPane.addTab("SM2",null,panel1,"First panel");  
        tabbedPane.addTab("SM3",null,panel2,"Second panel");  
        tabbedPane.addTab("SM4",null,panel3,"Third panel");  
  
        c.add(tabbedPane);  
        c.setBackground(Color.white);  
  
        setVisible(true);  
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);  
        
    }  
    
    private void SM2Frame(){
    	//创建button、label、TextArea
    	final JButton button1 = new JButton("加密");
        final JButton button2 = new JButton("解密");
        final JButton button3 = new JButton("签名");
        final JButton button4 = new JButton("验签");
        final JButton button5 = new JButton("密钥协商");
        final JButton button6 = new JButton("加密");
        final JButton button7 = new JButton("解密");
        final JButton button8 = new JButton("清空");
        final JButton button9 = new JButton("返回SM2选项");
        final JButton button10 = new JButton("签名");
        final JButton button11 = new JButton("验证");
        final JButton button12 = new JButton("开始协商");
		final JLabel label1 = new JLabel("待处理数据：");
		final JLabel label2 = new JLabel("加密结果:");
		final JLabel label3 = new JLabel("解密结果:");
		final JLabel label4 = new JLabel("用户标识:");
		final JLabel label5 = new JLabel("数字签名:");
		final JLabel label6 = new JLabel("数字签名:");
		final JLabel label7 = new JLabel("验证结果:");
    	final JTextArea textarea1 = new JTextArea(10,35);
    	final JTextArea textarea2 = new JTextArea(10,35);
    	final JTextArea textarea3 = new JTextArea(10,35);
    	final JTextArea textarea4 = new JTextArea(10,35);
    	textarea1.setLineWrap(true);
    	textarea2.setLineWrap(true);
    	textarea3.setLineWrap(true);
    	textarea4.setLineWrap(true);
        
        //添加button
        panel1.add(button1);
        panel1.add(button2);
        panel1.add(button3);
        panel1.add(button4);
        panel1.add(button5);
        panel1.add(label1);
        panel1.add(textarea1);
        panel1.add(label4);
        panel1.add(textarea3);
        panel1.add(label6);
        panel1.add(textarea4);
        panel1.add(button6);
        panel1.add(button7);
        panel1.add(button8);
        panel1.add(button9);
        panel1.add(button10);
        panel1.add(button11);
        panel1.add(button12);
        panel1.add(label2);
        panel1.add(label3);
        panel1.add(label5);
        panel1.add(label7);
        panel1.add(textarea2);

    	button1.setVisible(true);
    	button2.setVisible(true);
    	button3.setVisible(true);
    	button4.setVisible(true);
    	button5.setVisible(true);
    	button6.setVisible(false);
    	button7.setVisible(false);
    	button8.setVisible(false);
    	button9.setVisible(false);
    	button10.setVisible(false);
    	button11.setVisible(false);
    	button12.setVisible(false);
    	textarea1.setVisible(false);
    	textarea2.setVisible(false);
    	textarea3.setVisible(false);
    	textarea4.setVisible(false);
    	label1.setVisible(false);
    	label2.setVisible(false);
    	label3.setVisible(false);
    	label4.setVisible(false);
    	label5.setVisible(false);
    	label6.setVisible(false);
    	label7.setVisible(false);
    	
    	//选择加密
    	ActionListener C = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    	    	button1.setVisible(false);
    	    	button2.setVisible(false);
    	    	button3.setVisible(false);
    	    	button4.setVisible(false);
    	    	button5.setVisible(false);
    	    	button6.setVisible(true);
    	    	button7.setVisible(false);
    	    	button8.setVisible(true);
    	    	button9.setVisible(true);
    	    	button10.setVisible(false);
    	    	button11.setVisible(false);
    	    	button12.setVisible(false);
    	    	textarea1.setVisible(true);
    	    	textarea2.setVisible(true);	
    	    	textarea3.setVisible(false);
    	    	textarea4.setVisible(false);
    	    	label1.setVisible(true);
    	    	label2.setVisible(true);
    	    	label3.setVisible(false);
    	    	label4.setVisible(false);
    	    	label5.setVisible(false);
    	    	label6.setVisible(false);
    	    	label7.setVisible(false);
    	    	
    	    	textarea1.setText("");
    	    	textarea2.setText("");
    	    	textarea3.setText("");
    	    	textarea4.setText("");
    	    }
    	};
    	button1.addActionListener(C);
    	
    	//加密
    	ActionListener I = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    	    	button1.setVisible(false);
    	    	button2.setVisible(false);
    	    	button3.setVisible(false);
    	    	button4.setVisible(false);
    	    	button5.setVisible(false);
    	    	button6.setVisible(true);
    	    	button7.setVisible(false);
    	    	button8.setVisible(true);
    	    	button9.setVisible(true);
    	    	button10.setVisible(false);
    	    	button11.setVisible(false);
    	    	button12.setVisible(false);
    	    	textarea1.setVisible(true);
    	    	textarea2.setVisible(true);
    	    	textarea3.setVisible(false);
    	    	textarea4.setVisible(false);
    	    	label1.setVisible(true);
    	    	label2.setVisible(true);
    	    	label3.setVisible(false);
    	    	label4.setVisible(false);
    	    	label5.setVisible(false);
    	    	label6.setVisible(false);
    	    	label7.setVisible(false);
    	    	
    	    	SM2 sm02 = new SM2();
    			/* 也可以从文件导入密钥对 */
    			ECPoint pubKey = sm02.importPublicKey("publickey.pem");
    			BigInteger privKey = sm02.importPrivateKey("privatekey.pem");
    			/* 加密 */
    			String plainText = textarea1.getText();
    			byte[] data = sm02.encrypt(plainText, pubKey);  			
    			String ciphertext=SM2.getHexString(data);
    			textarea2.setText(ciphertext);
    	    	
    	    }
    	};
    	button6.addActionListener(I);
    	
    	//选择解密
    	ActionListener D = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    	    	button1.setVisible(false);
    	    	button2.setVisible(false);
    	    	button3.setVisible(false);
    	    	button4.setVisible(false);
    	    	button5.setVisible(false);
    	    	button6.setVisible(false);
    	    	button7.setVisible(true);
    	    	button8.setVisible(true);
    	    	button9.setVisible(true);
    	    	button10.setVisible(false);
    	    	button11.setVisible(false);
    	    	button12.setVisible(false);
    	    	textarea1.setVisible(true);
    	    	textarea2.setVisible(true);
    	    	textarea3.setVisible(false);
    	    	textarea4.setVisible(false);
    	    	label1.setVisible(true);
    	    	label2.setVisible(false);
    	    	label3.setVisible(true);
    	    	label4.setVisible(false);
    	    	label5.setVisible(false);
    	    	label6.setVisible(false);
    	    	label7.setVisible(false);
    	    	
    	    	textarea1.setText("");
    	    	textarea2.setText("");  	    	
    	    	textarea3.setText("");
    	    	textarea4.setText("");
    	    }
    	};
    	button2.addActionListener(D);
    	
    	//解密
    	ActionListener J = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    	    	button1.setVisible(false);
    	    	button2.setVisible(false);
    	    	button3.setVisible(false);
    	    	button4.setVisible(false);
    	    	button5.setVisible(false);
    	    	button6.setVisible(false);
    	    	button7.setVisible(true);
    	    	button8.setVisible(true);
    	    	button9.setVisible(true);
    	    	button10.setVisible(false);
    	    	button11.setVisible(false);
    	    	button12.setVisible(false);
    	    	textarea1.setVisible(true);
    	    	textarea2.setVisible(true);
    	    	textarea3.setVisible(false);
    	    	textarea4.setVisible(false);
    	    	label1.setVisible(true);
    	    	label2.setVisible(false);
    	    	label3.setVisible(true);
    	    	label4.setVisible(false);
    	    	label5.setVisible(false);
    	    	label6.setVisible(false);
    	    	label7.setVisible(false);
    	    	
    	    	String data = textarea1.getText();
    	    	
    	    	byte[] ciphertext=SM2.hexStringToBytes(data);
    	    	SM2 sm02 = new SM2();
    			/* 也可以从文件导入密钥对 */
    			ECPoint pubKey = sm02.importPublicKey("publickey.pem");
    			BigInteger privKey = sm02.importPrivateKey("privatekey.pem");
    			/* 解密 */
    			String plainText = sm02.decrypt(ciphertext, privKey);
    			textarea2.setText(plainText);
    	 
    	    }
    	};
    	button7.addActionListener(J);
    	
    	//选择签名
    	ActionListener E = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    	    	button1.setVisible(false);
    	    	button2.setVisible(false);
    	    	button3.setVisible(false);
    	    	button4.setVisible(false);
    	    	button5.setVisible(false);
    	    	button6.setVisible(false);
    	    	button7.setVisible(false);
    	    	button8.setVisible(true);
    	    	button9.setVisible(true);
    	    	button10.setVisible(true);
    	    	button11.setVisible(false);
    	    	button12.setVisible(false);
    	    	textarea1.setVisible(true);
    	    	textarea2.setVisible(true);
    	    	textarea3.setVisible(true);
    	    	textarea4.setVisible(false);
    	    	label1.setVisible(true);
    	    	label2.setVisible(false);
    	    	label3.setVisible(false);
    	    	label4.setVisible(true);
    	    	label5.setVisible(true);
    	    	label6.setVisible(false);
    	    	label7.setVisible(false);
    	    	
    	    	textarea1.setText("");
    	    	textarea2.setText("");
    	    	textarea3.setText("");
    	    	textarea4.setText("");
    	    }
    	};
    	button3.addActionListener(E);
    	
    	//签名
    	ActionListener Y = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    	    	button1.setVisible(false);
    	    	button2.setVisible(false);
    	    	button3.setVisible(false);
    	    	button4.setVisible(false);
    	    	button5.setVisible(false);
    	    	button6.setVisible(false);
    	    	button7.setVisible(false);
    	    	button8.setVisible(true);
    	    	button9.setVisible(true);
    	    	button10.setVisible(true);
    	    	button11.setVisible(false);
    	    	button12.setVisible(false);
    	    	textarea1.setVisible(true);
    	    	textarea2.setVisible(true);
    	    	textarea3.setVisible(true);
    	    	textarea4.setVisible(false);
    	    	label1.setVisible(true);
    	    	label2.setVisible(false);
    	    	label3.setVisible(false);
    	    	label4.setVisible(true);
    	    	label5.setVisible(true);
    	    	label6.setVisible(false);
    	    	label7.setVisible(false);
    	    	
//    	    	textarea1.setText("");
//    	    	textarea2.setText("");
//    	    	textarea3.setText("");
//    	    	textarea4.setText("");
    	    	
    			SM2 sm02 = new SM2();

    			/* 也可以从文件导入密钥对 */
    			ECPoint pubKey = sm02.importPublicKey("publickey.pem");
    			BigInteger privKey = sm02.importPrivateKey("privatekey.pem");
    			//System.out.println("公钥:\n" + pubKey);
    			//System.out.println("私钥:\n" + privKey.toString(16));
    			
//----------------------------------获取用户输入的IDA与待签名的消息M------------------------------------------//

    			String IDA = textarea3.getText();
    			String M = textarea1.getText();

    			Signature signature = sm02.sign(M, IDA, new SM2KeyPair(pubKey, privKey));

    			//System.out.println("用户标识:" + signature.r.toString(16));
    			//System.out.println("用户标识:" + signature.r.toString(16));
    			String sign=IDA + ",(" + signature.r.toString(16).toUpperCase() + "," + signature.s.toString(16).toUpperCase() + ")" ;
    			
//------------------------------将签名信息写到结果文本框中---------------------------------------------------//
    			textarea2.setText(sign);
//    			
//
//    			System.out.println("用户标识:" + IDA);
//    			System.out.println("签名信息:" + M);
//    			System.out.println("数字签名:" + signature);			
    	    	
    	    }
    	};
    	button10.addActionListener(Y);
    	
    	//选择验签
    	ActionListener F = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    	    	button1.setVisible(false);
    	    	button2.setVisible(false);
    	    	button3.setVisible(false);
    	    	button4.setVisible(false);
    	    	button5.setVisible(false);
    	    	button6.setVisible(false);
    	    	button7.setVisible(false);
    	    	button8.setVisible(true);
    	    	button9.setVisible(true);
    	    	button10.setVisible(false);
    	    	button11.setVisible(true);
    	    	button12.setVisible(false);
    	    	textarea1.setVisible(true);
    	    	textarea2.setVisible(true);
    	    	textarea3.setVisible(true);
    	    	textarea4.setVisible(true);
    	    	label1.setVisible(true);
    	    	label2.setVisible(false);
    	    	label3.setVisible(false);
    	    	label4.setVisible(true);
    	    	label5.setVisible(false);
    	    	label6.setVisible(true);
    	    	label7.setVisible(true);
    	    	
    	    	textarea1.setText("");
    	    	textarea2.setText("");
    	    	textarea3.setText("");
    	    	textarea4.setText("");    	    	
  	    	
    	    }
    	};
    	button4.addActionListener(F);
    	
    	//验签
    	ActionListener Z = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    	    	button1.setVisible(false);
    	    	button2.setVisible(false);
    	    	button3.setVisible(false);
    	    	button4.setVisible(false);
    	    	button5.setVisible(false);
    	    	button6.setVisible(false);
    	    	button7.setVisible(false);
    	    	button8.setVisible(true);
    	    	button9.setVisible(true);
    	    	button10.setVisible(false);
    	    	button11.setVisible(true);
    	    	button12.setVisible(false);
    	    	textarea1.setVisible(true);
    	    	textarea2.setVisible(true);
    	    	textarea3.setVisible(true);
    	    	textarea4.setVisible(true);
    	    	label1.setVisible(true);
    	    	label2.setVisible(false);
    	    	label3.setVisible(false);
    	    	label4.setVisible(true);
    	    	label5.setVisible(false);
    	    	label6.setVisible(true);
    	    	label7.setVisible(true);
    	    	
    	    	
    	    	SM2 sm02 = new SM2();
    			
    			/* 也可以从文件导入密钥对 */
    			ECPoint pubKey = sm02.importPublicKey("publickey.pem");
    			BigInteger privKey = sm02.importPrivateKey("privatekey.pem");

//---------------------获取用户输入的待验证消息M、用户标识IDA、待验证签名信息signature1--------------------------//
    			String M = textarea1.getText();
    			String IDA = textarea3.getText();
    			String signTemp = textarea4.getText();
    			
    			//String signTemp="(7caa05f622db19cf1151d3bcd645a581386a08d31d5e6e70f3b9c228589bb4cb,576d66f0e0120d88a05099e0de757e07688f71f1e5da4e883a45f9191d35074)";
    			signTemp = signTemp.replace("(", "");
    			signTemp = signTemp.replace(")", "");
    			
    			String signRS[]=signTemp.split(",");
    			
    			System.out.println(signRS[0]);
    			BigInteger r = new BigInteger(signRS[0], 16);
    			BigInteger s = new BigInteger(signRS[1], 16);
    			


    			Signature signature  = new Signature(r,s);
    			
    			System.out.println("验证签名:" + sm02.verify(M, signature, IDA, pubKey));
    			
    			 
    			
    			//sm02.verify(M, signature, IDA, publicKey));
    			
    			System.out.println("用户标识:" + IDA);
    			System.out.println("签名信息:" + M);
    			System.out.println("数字签名:" + signature);
    			System.out.println("验证签名:" + sm02.verify(M, signature, IDA, pubKey));
    			
//----------------------假设最终验证结果为flag，我这里先假设是true，将其写到结果框中--------------------------//
    			if (sm02.verify(M, signature, IDA, pubKey)) {
        			String flag = "true";
        			textarea2.setText(flag);
    			}
    			else {
        			String flag = "false";
        			textarea2.setText(flag);
				}
  
    	    }
    	};
    	button11.addActionListener(Z);
    	
    	//密钥协商
    	ActionListener G = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    	    	button1.setVisible(false);
    	    	button2.setVisible(false);
    	    	button3.setVisible(false);
    	    	button4.setVisible(false);
    	    	button5.setVisible(false);
    	    	button6.setVisible(false);
    	    	button7.setVisible(false);
    	    	button12.setVisible(true);
    	    	button8.setVisible(false);
    	    	button9.setVisible(true);
    	    	button10.setVisible(false);
    	    	button11.setVisible(false);
    	    	button12.setVisible(true);
    	    	textarea1.setVisible(true);
    	    	textarea2.setVisible(true);
    	    	
    	    	textarea1.setText("");
    	    	textarea2.setText("");
    	    }
    	};
    	button5.addActionListener(G);
    	
    	//开始协商
    	ActionListener TalkA = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    	    	button1.setVisible(false);
    	    	button2.setVisible(false);
    	    	button3.setVisible(false);
    	    	button4.setVisible(false);
    	    	button5.setVisible(false);
    	    	button6.setVisible(false);
    	    	button7.setVisible(false);
    	    	button12.setVisible(true);
    	    	button8.setVisible(false);
    	    	button9.setVisible(true);
    	    	button10.setVisible(false);
    	    	button11.setVisible(false);
    	    	textarea1.setVisible(true);
    	    	textarea2.setVisible(true);
    	    	
    	    	textarea1.setText("我是用户A\r\n");
    	    	textarea2.setText("我是用户B\r\n");
    	    	
    	    	SM2 sm02 = new SM2();
    	    	
    	    	//A进行初始化
    			String aID = "ALICE123@YAHOO.COM";
    			textarea1.append("我的ID为：" + aID + "\r\n");
    			SM2KeyPair aKeyPair = sm02.generateKeyPair();
    			KeyExchange aKeyExchange = new KeyExchange(aID, aKeyPair);
    			
    			//B进行初始化
    			String bID = "BILL456@YAHOO.COM";
    			textarea2.append("我的ID为：" + bID + "\r\n");
    			SM2KeyPair bKeyPair = sm02.generateKeyPair();
    			KeyExchange bKeyExchange = new KeyExchange(bID, bKeyPair);
    			
    			//A先生成entity1 发送RA
    			TransportEntity entity1 = aKeyExchange.keyExchange_1();
    			ECPoint aRTemp= aKeyExchange.RA;
    			String ra = SM2.getHexString(aRTemp.getRawXCoord().getEncoded());
    			textarea1.append("RA为：" + ra + "\r\n");
    			
    			//B拿到entity1 算出密钥 生成entity2 返回RB
    			TransportEntity entity2 = bKeyExchange.keyExchange_2(entity1);
    			byte[] bkeyTemp= bKeyExchange.key;
				String bkeyString= SM2.getHexString(bkeyTemp);
				textarea2.append("B得到密钥：" + bkeyString + "\r\n");
				ECPoint bRTemp= bKeyExchange.RA;
    			String rb = SM2.getHexString(bRTemp.getRawXCoord().getEncoded());
    			textarea2.append("RB为：" + rb + "\r\n");
    			//A拿到entity2 算出密钥 生成entity3
    			TransportEntity entity3 = aKeyExchange.keyExchange_3(entity2);
    			byte[] akeyTemp= bKeyExchange.key;
				String akeyString= SM2.getHexString(akeyTemp);
				textarea1.append("A得到密钥：" + akeyString + "\r\n");
    			//B拿到entity3 确认密钥
    			bKeyExchange.keyExchange_4(entity3);
    			
    	    	
    	    }
    	};
    	button12.addActionListener(TalkA);
    	
    	//清空
    	ActionListener clean = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    			textarea1.setText("");
    			textarea2.setText("");
    			textarea3.setText("");
    			textarea4.setText("");
    	    }
    	};
    	button8.addActionListener(clean);
    	
    	//返回SM2
    	ActionListener RESM2 = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    			button1.setVisible(true);
    	    	button2.setVisible(true);
    	    	button3.setVisible(true);
    	    	button4.setVisible(true);
    	    	button5.setVisible(true);
    	    	button6.setVisible(false);
    	    	button7.setVisible(false);
    	    	button8.setVisible(false);
    	    	button9.setVisible(false);
    	    	button10.setVisible(false);
    	    	button11.setVisible(false);
    	    	button12.setVisible(false);
    	    	textarea1.setVisible(false);
    	    	textarea2.setVisible(false);
    	    	textarea3.setVisible(false);
    	    	textarea4.setVisible(false);
    	    	label1.setVisible(false);
    	    	label2.setVisible(false);
    	    	label3.setVisible(false);
    	    	label4.setVisible(false);
    	    	label5.setVisible(false);
    	    	label6.setVisible(false);
    	    	label7.setVisible(false);
    	    }
    	};
    	button9.addActionListener(RESM2);
    }
    
    private void SM3Frame(){

        final JTextArea textarea1 = new JTextArea(10,35);
        final JTextArea textarea2 = new JTextArea(10,35);
        JButton button1 = new JButton("加密");
        JButton button2 = new JButton("清空");
        JLabel label1 = new JLabel("加密结果：");
        
        panel2.add(textarea1);
        panel2.add(button1);
        panel2.add(button2);
        panel2.add(label1);
        panel2.add(textarea2);
        
    	ActionListener E = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
//--------------------------------------获取用户输入-----------------------------------------------//
    			String plaintext = textarea1.getText();
    			
    			String ciphertext = "加密结果";
//--------------------------------------展示加密结果-----------------------------------------------//
    			textarea2.setText(ciphertext);
    	    }
    	};
    	button1.addActionListener(E);
    	
    	ActionListener clean = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    			textarea1.setText("");
    			textarea2.setText("");
    	    }
    	};
    	button2.addActionListener(clean);
    }
    
    public void SM4Frame() {
    	final JButton button1 = new JButton("ECB模式");
    	final JButton button2 = new JButton("CBC模式");
		final JButton button3 = new JButton("加密ECB");
		final JButton button4 = new JButton("加密CBC");
		final JButton button5 = new JButton("解密ECB");
		final JButton button6 = new JButton("解密CBC");
		final JButton button7 = new JButton("清空");
		final JButton button8 = new JButton("返回SM4选项");
		final JLabel label1 = new JLabel("加密结果：");
		final JLabel label2 = new JLabel("解密结果：");
		final JLabel label3 = new JLabel("待处理数据：");
		final JLabel label4 = new JLabel("密钥：");
		final JLabel label5 = new JLabel("IV值：");
		final JTextArea textarea = new JTextArea(20,35);
		final JTextArea key = new JTextArea(2,10);
		final JTextArea iv= new JTextArea(2,10);
		final JTextArea output = new JTextArea(20,35);
    	panel3.add(button1);
    	panel3.add(button2);
    	panel3.add(label3);
		panel3.add(textarea);
    	panel3.add(label4);
    	panel3.add(key);
    	panel3.add(label5);
    	panel3.add(iv);
    	panel3.add(button3);
    	panel3.add(button4);
    	panel3.add(button5);
    	panel3.add(button6);
    	panel3.add(button7);
    	panel3.add(button8);
    	panel3.add(label1);
    	panel3.add(label2);
    	panel3.add(output);
    	button1.setVisible(true);
    	button2.setVisible(true);
    	button3.setVisible(false);
    	button4.setVisible(false);
    	button5.setVisible(false);
    	button6.setVisible(false);
    	button7.setVisible(false);
    	button8.setVisible(false);
    	textarea.setVisible(false);
    	key.setVisible(false);
    	iv.setVisible(false);
    	output.setVisible(false);
    	label1.setVisible(false);
    	label2.setVisible(false);
    	label3.setVisible(false);
    	label4.setVisible(false);
    	label5.setVisible(false);
    	//ECB模式
    	ActionListener C = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    	    	button1.setVisible(false);
    	    	button2.setVisible(false);
    	    	button3.setVisible(true);
    	    	button5.setVisible(true);
    	    	button7.setVisible(true);
    	    	button8.setVisible(true);
    	    	textarea.setVisible(true);
    	    	//label1.setVisible(true);
    	    	//output.setVisible(true);
    	    	label3.setVisible(true);
    	    	label4.setVisible(true);
    	    	key.setVisible(true);
    	    	textarea.setText("");
    	    	key.setText("");
    	    }
    	};
    	//CBC模式
    	button1.addActionListener(C);
    	
    	ActionListener D = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    	    	button1.setVisible(false);
    	    	button2.setVisible(false);
    	    	button4.setVisible(true);
    	    	button6.setVisible(true);
    	    	button7.setVisible(true);
    	    	button8.setVisible(true);
    	    	textarea.setVisible(true);
    	    	label3.setVisible(true);
    	    	label4.setVisible(true);
    	    	label5.setVisible(true);
    	    	//label2.setVisible(true);
    	    	//output.setVisible(true);
    	    	key.setVisible(true);
    	    	iv.setVisible(true);
    	    	textarea.setText("");
    	    	key.setText("");
    	    	iv.setText("");
    	    }
    	};
    	button2.addActionListener(D);
    	//ECB模式加密
    	ActionListener ECB_C = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    			label2.setVisible(true);
    	    	output.setVisible(true);
    			String plainText = textarea.getText();
    			SM4Utils sm4 = new SM4Utils();
    			sm4.secretKey = key.getText();
    			sm4.hexString = false;
    			String cipherText = sm4.encryptData_ECB(plainText);
    			output.setText(cipherText);
    			//textarea.setText("");
    			//key.setText(" ");
    	    }
    	};
    	button3.addActionListener(ECB_C);
    	
    	//CBC模式加密
    	ActionListener CBC_C = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    			label2.setVisible(true);
    	    	output.setVisible(true);
    			String plainText = textarea.getText();
    			SM4Utils sm4 = new SM4Utils();
    			sm4.secretKey = key.getText();
    			sm4.hexString = false;
    			sm4.iv = iv.getText();
    			String cipherText = sm4.encryptData_CBC(plainText);
    			output.setText(cipherText);
    	    }
    	};
    	button4.addActionListener(CBC_C);
    	//ECB模式解密
    	ActionListener ECB_E = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    			label2.setVisible(true);
    	    	output.setVisible(true);
    			String plainText = textarea.getText();
    			SM4Utils sm4 = new SM4Utils();
    			sm4.secretKey = key.getText();
    			sm4.hexString = false;
    			String cipherText = sm4.decryptData_ECB(plainText);
    			output.setText(cipherText);
    	    }
    	};
    	button5.addActionListener(ECB_E);
    	//CBC模式解密
    	ActionListener CBC_E = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    			label2.setVisible(true);
    	    	output.setVisible(true);
    			String plainText = textarea.getText();
    			SM4Utils sm4 = new SM4Utils();
    			sm4.secretKey = key.getText();
    			sm4.hexString = false;
    			sm4.iv = iv.getText();
    			String cipherText = sm4.decryptData_CBC(plainText);
    			output.setText(cipherText);
    	    }
    	};
    	button6.addActionListener(CBC_E);
    	//清空输入框
    	ActionListener clean = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    			textarea.setText("");
    	    	key.setText("");
    	    	iv.setText("");
    	    	output.setText("");
    	    	output.setVisible(false);
    	    }
    	};
    	button7.addActionListener(clean);
    	
    	//返回
    	ActionListener RESM4 = new ActionListener() {
    		public void actionPerformed(ActionEvent evt) {
    	    	button1.setVisible(true);
    	    	button2.setVisible(true);
    	    	button3.setVisible(false);
    	    	button4.setVisible(false);
    	    	button5.setVisible(false);
    	    	button6.setVisible(false);
    	    	button7.setVisible(false);
    	    	button8.setVisible(false);
    	    	textarea.setVisible(false);
    	    	key.setVisible(false);
    	    	iv.setVisible(false);
    	    	output.setVisible(false);
    	    	label1.setVisible(false);
    	    	label2.setVisible(false);
    	    	label3.setVisible(false);
    	    	label4.setVisible(false);
    	    	label5.setVisible(false);
    	    }
    	};
    	button8.addActionListener(RESM4);
    }
    
    public static void main(String args[])  
    {  
        UI d = new UI();
        d.SM2Frame();
        d.SM3Frame();
        d.SM4Frame();
        
    }  
}  
