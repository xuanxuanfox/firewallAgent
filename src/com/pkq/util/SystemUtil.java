package com.pkq.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.SequenceInputStream;

public class SystemUtil {
	public static String runCommand(String command) throws Exception {
		StringBuffer sb = new StringBuffer();
		try {
			Process process = Runtime.getRuntime().exec(command
					);
			SequenceInputStream sis = new SequenceInputStream(process
					.getInputStream(), process.getErrorStream());
			//InputStreamReader isr = new InputStreamReader(sis, "utf-8");
			InputStreamReader isr = new InputStreamReader(sis);
			BufferedReader br = new BufferedReader(isr);
			// next command
			OutputStreamWriter osw = new OutputStreamWriter(process
					.getOutputStream());
			BufferedWriter bw = new BufferedWriter(osw);
			String line = null;
			while (null != (line = br.readLine())) {
				//System.out.println(line);
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
}
