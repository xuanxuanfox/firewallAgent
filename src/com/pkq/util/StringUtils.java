package com.pkq.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author lei 2011-9-2
 */
public class StringUtils {

	public static String replaceBlank(String str) {
		String dest = "";
		if (str != null) {
			Pattern p = Pattern.compile("\\s*|\t|\r|\n"); 
			Matcher m = p.matcher(str);
			dest = m.replaceAll("");
			dest = dest.trim();
		}
		return dest;
	}

	public static void main(String[] args) {
		System.out.println(StringUtils.replaceBlank("  just do it!   \n \r\n "));
	}

}
