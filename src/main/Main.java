package main;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

import javax.swing.*;

import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Main {
	
	public static String password = null;
	public static String key = null;
	public static ArrayList<String> fileNames = null;
	public static final String MASTER_PASSWORD_FILE = "master_password.enc";
	
	/*
	 * The notion here is simple: at start-up, try to detect a local master password file.
	 * The master password file contains two pieces of data. The word "CORRECT" and
	 * a hash key that was used to encrypt all other local files. If there's no local master file,
	 * then you ask for a master password, then create a local file using the MP as the encryption key.
	 * 
	 * You enter a master password which ideally decrypts the master password file. Once that's
	 * decrypted, you can decrypt all the other files.
	 */
	public static void main(String[] args) throws Exception {
		long lastInteracted = new Date().getTime();
		File localDirectory = null;
		
		try{
			localDirectory = new File(Main.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath());
		} catch(Exception e) {
			JOptionPane.showMessageDialog(null, e.getMessage());
		}
		
		System.out.println("Local directory found at : " + localDirectory);
		
		accessData(localDirectory, false);
		System.out.println("Main data accessed");
		
		System.out.println("Getting file names.");
		fileNames = getFileNames(localDirectory);
		System.out.println("File names retrieved.");
		
		String input = "";
		while(!input.equalsIgnoreCase("q")) {
			
			// 10 minutes have passed without an action, so we re-query for master password.
			long curTime = new Date().getTime();
			if(curTime - lastInteracted > 600000) { 
				password = null;
				key = null;
				accessData(localDirectory, true);
			}
			
			// Now main action sequence.
			String fileName = copyInput("To get a password, just copy and paste a filename "
					+ "from the list below. If you want to add a new filename, just type in 'new'\n\n\n "
					+ fileNamesStr());
			
			if(fileName.equalsIgnoreCase("new")) {
				String name = JOptionPane.showInputDialog(null, "Name of new file (leave out the extension)?");
				name += ".enc";
				String pw = JOptionPane.showInputDialog(null, "Password to remember.");
				
				byte[] newEncr = encrypt(pw, key);
				writeBytesToFile(localDirectory, name, newEncr);
				fileNames.add(name);
				JOptionPane.showMessageDialog(null, "New password saved with name: " + name);
			} else {
				byte[] data = Files.readAllBytes(Paths.get(localDirectory + "\\" + fileName));
				JOptionPane.showMessageDialog(null, decrypt(data, key));
			}
		}
	}
	
	public static String fileNamesStr() {
		StringBuilder sb = new StringBuilder();
		for(String str : fileNames) {
			sb.append(str + "\n");
		}
		return sb.toString();
	}
	
	public static String copyInput(String text) {
		JTextArea ta = new JTextArea(10, 10);
        ta.setText(text);
        ta.setWrapStyleWord(true);
        ta.setLineWrap(true);
        ta.setCaretPosition(0);
        ta.setEditable(false);

        return JOptionPane.showInputDialog(null, new JScrollPane(ta), "RESULT", JOptionPane.INFORMATION_MESSAGE);
	}
	
	public static ArrayList<String> getFileNames(File localDirectory) {
		File[] listOfFiles = localDirectory.listFiles();
		
		ArrayList<String> fileNames = new ArrayList<String>();
		
		for(File file : listOfFiles) {
			if(file.getName().contains(".enc")) {
				fileNames.add(file.getName());
			}
		}
		
		return fileNames;
	}
	
	public static void writeBytesToFile(File localDirectory, String fileName, byte[] bytes) throws Exception{
		File file = new File(localDirectory, fileName);
		if(file.createNewFile()) {
			System.out.println("File with name " + fileName + " created.");
		}
		
		BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file));
		bos.write(bytes);
		bos.flush();
		bos.close();
	}
	
	public static void accessData(File localDirectory, boolean dueToTimeout) throws Exception {
		if(new File(localDirectory, MASTER_PASSWORD_FILE).exists()) {
			// Input proposed master password.
			if(dueToTimeout) {
				password = JOptionPane.showInputDialog(null, "Timed out after 10 minutes of inactivity, re-enter master password");
			} else {
				password = JOptionPane.showInputDialog(null, "Enter your master password to decrypt local files.");
			}
			byte[] data = Files.readAllBytes(Paths.get(localDirectory + "\\" + MASTER_PASSWORD_FILE));
			
			String[] rawData = null;
			
			try {
				rawData = decrypt(data, password).split("\n");
			} catch(Exception e) {
				JOptionPane.showMessageDialog(null, "Bad password... or something got corrupted.\n\n" + e.getMessage());
				throw new Exception();
			}
			if(!rawData[0].equals("CORRECT")) {
				JOptionPane.showMessageDialog(null, "Bad password!");
				throw new Exception();
			}
			
			key = rawData[1];
		} else {
			password = JOptionPane.showInputDialog(null, "Enter your new master password. You _NEED_ to remember this!");
			
			key = getRandomChars(60);
			String masterContents = "CORRECT\n" + key;
			System.out.println("masterContents created. This is: \n" + masterContents);
			
			
			byte[] encryptedContents = encrypt(masterContents, password);
			writeBytesToFile(localDirectory, MASTER_PASSWORD_FILE, encryptedContents);
		    
		    System.out.println("Master contents written.");   
		}
	}
	
	public static byte[] encrypt(String str, String pass) throws Exception {
		MessageDigest sha = MessageDigest.getInstance("MD5");
        byte[] key = sha.digest(pass.getBytes());
        System.out.println("Key length is: " + key.length);
		Key aesKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal(str.getBytes());
        return encrypted;
	}
	
	public static String decrypt(byte[] encrypted, String pass) throws Exception {
		MessageDigest sha = MessageDigest.getInstance("MD5");
        byte[] key = sha.digest(pass.getBytes());
        System.out.println("Key length is: " + key.length);
		Key aesKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        String decrypted = new String(cipher.doFinal(encrypted));
        
        return decrypted;
	}
	
	// Alphanumeric + symbols.
	public static String getRandomChars(int length) {
		String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()[]{}";
		StringBuilder sb = new StringBuilder();
		
		Random rand = new Random();
		
		for(int i = 0; i < length; i++) {
			sb.append(chars.charAt(rand.nextInt(chars.length())));
		}
		
		return sb.toString();
	}
}
