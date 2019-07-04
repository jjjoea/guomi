package GUI;

import java.awt.FlowLayout;
import java.awt.Frame;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;




import java.awt.*;
import java.awt.event.*;
import java.io.*;
 
public class gui
{
	public static void main(String[] args) 
	{
		new MyWindow();
	}
}
 
class MyWindow 
{
	private Frame f;
	private TextField tf;
	private TextArea ta;
	private Button but;
 
	MyWindow()
	{
		init();
	}
 
	
	public void init()
	{
		f=new Frame("123");
		f.setBounds(300,200,600,400);
		f.setLayout(new FlowLayout());
 
		tf=new TextField(50);
		ta=new TextArea(20,70);
		but=new Button("转到22");
 
		f.add(tf);
		f.add(but);
		f.add(ta);
 
		myEvent();
 
		f.setVisible(true);
	}
 
	//事件处理
	public void myEvent()
	{
		//对窗体注册窗口监听器
		f.addWindowListener(new WindowAdapter()
		{
			public void windowClosing(WindowEvent e)
			{
				System.exit(0);
			}
		});
		
		//对按钮注册活动监听器
		but.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent e)
			{
				showDir();
			}
		});
		
		//对文本框注册键盘监听器
		tf.addKeyListener(new KeyAdapter()
		{
			public void keyPressed(KeyEvent e)
			{
				if (e.getKeyCode()==e.VK_ENTER)
				{
					showDir();
				}
			}
		});
 
	}
	
	//列出文本框中指定目录的内容
	public void showDir()
	{
		//获取文本框的内容
		String dir=tf.getText();
 
		File file=new File(dir);
		if (file.exists()&&file.isDirectory())
		{
			//清空文本区域的内容
			ta.setText("");
 
			String[] str=file.list();
			for(String s:str)
			{
				//将遍历的内容追加到文本区域中，并进行换行
				ta.append(s+"\t\n");
			}
			
			//清空文本框的内容
			tf.setText("");
		}
	}
 
}
 
 