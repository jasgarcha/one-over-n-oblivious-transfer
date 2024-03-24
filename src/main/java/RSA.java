/*Modified https://introcs.cs.princeton.edu/java/99crypto/RSA.java.html*/

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
	private final BigInteger modulus; //p*q. Modulus.
	private final BigInteger publicKey; //Public key.
	private final BigInteger privateKey; //Private key.

	private final static SecureRandom random = new SecureRandom(); 

	//Generate an N-bit (roughly) public and private key pair.
	public RSA(int N) {
		//p, q: distinct, large prime numbers.
		BigInteger p = BigInteger.probablePrime(N/2, random); 
		BigInteger q = BigInteger.probablePrime(N/2, random);		
		BigInteger n = p.multiply(q); //n = p*q. Modulus.	
		BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE)); //(p-1)*(q-1).  
		BigInteger e; //Public exponent e, relatively prime to (p-1)*(q-1).
		BigInteger d; //Private exponent d, such that e*d = 1 mod (p-1)*(q-1).

		//Generate public exponent e. 
		//(p-1)*(q-1) and public key e must be relatively prime: gcd((p-1)*(q-1), e) = 1. 
		//In the case gcd(phi, publicKey) != 1 (phi is a multiple of the public key) key generation fails. Loop to generate keys until the gcd is 1.
		do {
			e = BigInteger.probablePrime(phi.bitLength(), random);
		}
		while(e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE)); //Relative prime check. gcd((p-1)*(q-1), e) = 1. 

		//assert gcd(phi.intValue(), e.intValue()) == 1;
		
		//Generate private exponent d, such that e*d = 1 mod (p-1)*(q-1).
		//Use the Extended Euclidean Algorithm to determine the modular inverse.
		//int val[] = gcd(e, phi);
		//d = val[0].
		
		d = e.modInverse(phi);

		modulus    = n; //Modulus. n = p*q, size N.
		publicKey  = e; //Public key = (Public exponent=e, modulus=n=p*q).
		privateKey = d; //Private key = private exponent = d = publicKey.modInverse(phi);
	}
	
	public BigInteger getPublicKey() {
		return publicKey;
	}

	public BigInteger getPrivateKey() {
		return privateKey;
	}

	public BigInteger getModulus() {
		return modulus;
	}

	//encrypt(M) = M^e mod PQ = M^public key mod modulus.
	public static BigInteger encrypt(BigInteger publicKey, BigInteger modulus, BigInteger message) {		
		return message.modPow(publicKey, modulus);
	}

	//decrypt(E) = E^d mod PQ = E^private key mod modulus.
	public static BigInteger decrypt(BigInteger privateKey, BigInteger modulus, BigInteger encrypted) {
		return encrypted.modPow(privateKey, modulus);
	}
}