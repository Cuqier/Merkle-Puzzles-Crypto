/*
Merkle-Puzzles with generation and simulated breaking procedure
---------------------------------->
Standarized puzzle amount is 2^16 for this one
Example, to enforce X(2^32) time for attacker, there need to be generated X(2^16) total amount of puzzles
*/

import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import java.io.*;


// In case of using in real project use class below:
//import java.util.Random;
import java.security.SecureRandom;
import java.math.BigInteger;

class Merkle {
  Cipher cipher;


  private Random random = new SecureRandom();

  Merkle() {
    try {
      cipher = Cipher.getInstance("DES");
    } catch (NoSuchPaddingException e) {
    } catch (java.security.NoSuchAlgorithmException e) {
    }
  }

  public String random_string(int length) {
    // Alphabet range is [a-z0-9]
    String k = new BigInteger(400, random).toString(32);
    k = k.substring(0, length);
    return k;
  }

  public SecretKey random_key(int length) {
    // Pad with zeroes in the case if string is to short
    byte[] k = (this.random_string(length) + "00000000").getBytes();
    // Uses the first 8 bytes for key material -- any extra is ignored
    // (8 bytes - 1 bit of parity for each byte = 56 bits)
    try {
      DESKeySpec sks = new DESKeySpec(k);
      SecretKeyFactory sf = SecretKeyFactory.getInstance("DES");
      return sf.generateSecret(sks);
    } catch (InvalidKeySpecException e) {
    } catch (java.security.NoSuchAlgorithmException e) {
    } catch (java.security.InvalidKeyException e) {
    }
    return null;
  }

  public byte[] encrypt(SecretKey key, String data) throws java.security.InvalidKeyException {
    try {
      cipher.init(Cipher.ENCRYPT_MODE, key);
      byte[] utf8 = data.getBytes("UTF8");
      byte[] ciphertext = cipher.doFinal(utf8);
      return ciphertext;
    } catch (BadPaddingException e) {
    } catch (IllegalBlockSizeException e) {
    } catch (UnsupportedEncodingException e) {
    }
    return null;
  }

  public String decrypt(SecretKey key, byte[] ciphertext) {
    try {
      cipher.init(Cipher.DECRYPT_MODE, key);
      byte[] utf8 = cipher.doFinal(ciphertext);
      return new String(utf8, "UTF8");
    } catch (BadPaddingException e) {
    } catch (IllegalBlockSizeException e) {
    } catch (UnsupportedEncodingException e) {
    } catch (java.security.InvalidKeyException e) {
    }
    return null;
  }

  public static void main (String[] args) throws java.security.InvalidKeyException {
    Merkle mkl = new Merkle();

    //// Variables for setup
    int totalPuzzles = 16777216;
    int keyLen = 3;
    // Key length greater than 8 doesn't work DES only accepts 7 bytes (8 * 7 = 56 bits)
    if (args.length > 0) {
      keyLen = Integer.parseInt(args[0]);
    }
    System.out.println("Random key string is of length " + keyLen);
    System.out.println();

    // Random puzzles generation
    System.out.println("Generating " + totalPuzzles + " puzzles...");
    ArrayList<byte[]> puzzles = new ArrayList<byte[]>();
    for(int i = 0; i < totalPuzzles; ++i) {
      byte[] ciphertext = mkl.encrypt(mkl.random_key(keyLen), "Key=" + mkl.random_string(30) + " & Puzzle=" + i);
      puzzles.add(ciphertext);
    }
    System.out.println("Process execution...");
    System.out.println();

    System.out.println("Merkle's Puzzles Generation");
    Collections.shuffle(puzzles);
    System.out.println();

    // Let's select a puzzle at random and solve it
    int chosen = mkl.random.nextInt(puzzles.size());
    System.out.println("Attempting to brute force random ciphertext #" + chosen + "... ");
    boolean solved = false;
    int attempts = 0;
    while(!solved) {
      ++attempts;
      String plaintext = mkl.decrypt(mkl.random_key(keyLen), (byte[])puzzles.get(chosen));
      // Note that we need to check the message is structured as we could decrypt to garbage
      if (plaintext != null && plaintext.substring(0,4).equals("Key=")) {
        System.out.println("Solved in " + attempts + " attempts: " + plaintext);
        solved = true;
      }
    }
    System.out.println("Shit! The puzzles has been cracked!");
  }
}
