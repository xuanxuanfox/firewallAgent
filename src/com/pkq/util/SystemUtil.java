package com.pkq.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.SequenceInputStream;

public class SystemUtil {
	public static void main(String[] args) {
		String cmd = "C:\\pkqfirewall\\wget-1_5_3_1\\wget.exe -P C:\\pkqfirewall\\agentUpdate\\download http://192.168.9.1:8080/pkqfirewall/upload/pkqfirewallAgent.zip";
		try {
			String ret = runCommand(cmd);
			System.out.println(ret);
			//runCommandPrint(cmd);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static String runCommand(String command) throws Exception {
		StringBuffer sb = new StringBuffer();
		try {
			Process process = Runtime.getRuntime().exec(command);
			SequenceInputStream sis = new SequenceInputStream(process
					.getInputStream(), process.getErrorStream());
			// InputStreamReader isr = new InputStreamReader(sis, "utf-8");
			InputStreamReader isr = new InputStreamReader(sis);
			BufferedReader br = new BufferedReader(isr);
			// next command
			OutputStreamWriter osw = new OutputStreamWriter(process
					.getOutputStream());
			BufferedWriter bw = new BufferedWriter(osw);
			String line = null;
			while (null != (line = br.readLine())) {
				// System.out.println(line);
				sb.append(line).append("\r\n");
			}

			process.destroy();
			br.close();
			isr.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return sb.toString();
	}

	public static void runCommandPrint(String command) {
		try {
			Process child = Runtime.getRuntime().exec(command);
			//InputStream in = child.getInputStream();
			//BufferedReader br = new BufferedReader(new InputStreamReader(in));

			//String line = br.readLine().toString();
			/*
			while (line != null) {
				System.out.println(line); // 输出测试
				line = br.readLine().toString();
			}
			*/
			try {
				//child.waitFor();
				//br.close();
				//in.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
