package com.pkq.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;

class Data{
	byte[] name = new byte[10];
	int age;
	byte[] father = new byte[10];

}

public class FileOp {

	public static String readTextFile( String fileName ) throws IOException{
			
			String str = ""; 
			byte[] bts = getBytesFromFile(fileName);	
			str = new String(bts,"UTF-8");
			return str;
	}
	
	public static void appendToTextFile( String fileName, String str ) throws IOException{
			//open for append
			BufferedWriter out = new BufferedWriter(new FileWriter( fileName, true));     
			out.write( str );     
			out.close();		
	}
	
    public static byte[] getBytesFromFile(String fileName) throws IOException {
    	File file = new File( fileName );
    	InputStream is = new FileInputStream(file);
    	long length = file.length();
    	
    	if (length > Integer.MAX_VALUE) 	{
    		throw new IOException( "File is too large" );        
    	}
    	byte[] bytes = new byte[(int)length];
    	int offset = 0;
    	int numRead = 0;
    	
    	numRead=is.read(bytes, offset, bytes.length-offset);
    	while (offset < bytes.length && numRead >= 0) 	{            
    		offset += numRead; 
    		numRead=is.read(bytes, offset, bytes.length-offset);
    	}
        if (offset < bytes.length) 	{
        	throw new IOException("Could not completely read file "+file.getName());        
        }
        is.close();
        return bytes;
    }

    public void appendBytesToFile(File file, byte[] buff ) throws IOException { 
    
	    try {     
	    	File f = new File("filename");     
	    	RandomAccessFile raf = new RandomAccessFile( file, "rw");
	    	raf.seek(f.length());
	    	
	    	raf.close();
	    	raf.write( buff );
	    }catch (IOException e) {}
    }
}
