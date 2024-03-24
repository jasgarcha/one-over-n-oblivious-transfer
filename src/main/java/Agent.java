/**
 * @author Jasminder Garcha
 */
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Base64;

//RSA based 1-n Oblivious Transfer Protocol simulator.
//I/O: ObjectInputStream/ObjectOutputStream.
//Agent.
public class Agent {
	private Object[] information; 
	private BigInteger modulus; 
	private BigInteger publicKey;
	private BigInteger privateKey;

	public Agent() {
		information = null;
		modulus = null;
		publicKey = null;
		privateKey = null;
	}

	public Agent(Object[] informationItems, int N) {
		setInformation(informationItems);		
		generateKeyPair(N);
	}

	private Object[] getInformation() {
		return information;
	}

	public BigInteger getModulus() {
		return modulus;
	}

	public BigInteger getPublicKey() {
		return publicKey;
	}

	public BigInteger getPrivateKey() {
		return privateKey;
	}

	public void setInformation(Object[] informationItems) {
		information = informationItems;		
	}

	public void generateKeyPair(int N) {
		RSA rsa = new RSA(N);
		modulus = rsa.getModulus();
		publicKey = rsa.getPublicKey();
		privateKey = rsa.getPrivateKey();
	}

	public static void main(String[] args) throws Exception {
		ServerSocket server = new ServerSocket(381); 
		Socket socket = server.accept(); //Accept connection from inquirer.		
		ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
		ObjectInputStream input = new ObjectInputStream(socket.getInputStream()); 		

		final Object[] information = {82, 57, 2, 31, 20, 64, 72, 97, 22, 8};

		Agent agent = new Agent();
		agent.setInformation(information);
		agent.generateKeyPair(256);

		Object[] I = agent.getInformation(); //I.
		BigInteger modulus = agent.getModulus();
		BigInteger publicKey = agent.getPublicKey();
		BigInteger privateKey = agent.getPrivateKey();

		SecureRandom random = new SecureRandom();

		//Send number of information items to inquirer.
		int n = I.length;
		
		output.writeInt(n);
		output.flush();

		//Receive k from inquirer.
		System.out.println("Receiving k from inquirer.");

		int k = input.readInt();

		System.out.println("k="+k+"\n");	

		//Send public key to inquirer.
		System.out.println("Sending public key to inquirer.");	

		System.out.println(Base64.getEncoder().encodeToString(publicKey.toByteArray())+"\n");

		output.writeObject(publicKey);
		output.flush();

		output.writeObject(modulus);
		output.flush();

		//Assume inquirer wants to know the kth information unit I[k].	

		//Step 1: Agent sends random numbers RN[1],...,RN[n] to the inquirer.	

		System.out.println("Sending random numbers RN[1],...,RN[n] to the inquirer.");
		
		//Generate random numbers RN[].
		BigInteger[] RN = new BigInteger[n];

		for(int i = 0; i < RN.length;) {
			for(int j = 0; j < RN.length; j++) {
				RN[j] = BigInteger.ZERO; 
				BigInteger randomNumber = new BigInteger(32, random);
				if(!RN[j].equals(randomNumber)) {
					RN[i] = randomNumber;				
					i++;
				}
			}			
		}
		
		for(int i = 0; i < RN.length; i++) {
			System.out.println("RN["+i+"]="+RN[i]);
		}
		System.out.println();
		
		output.writeObject(RN);
		output.flush();

		System.out.println("Receive K+(IRN)+RN[k] from inquirer.\n");
		
		BigInteger inquirerStep2 = (BigInteger)input.readObject(); //K+(IRN)+RN[k].

		//Step 3: Agent sends the inquirer the following n items K-(K+(IRN)+RN[k]-RN[i])+I[i] for i=1,...,n.	
		BigInteger[] agentStep3 = new BigInteger[n];		
		for(int i = 0; i < n; i++) {
			//The agent derives n terms K+(IRN)+RN[k]-RN[i] for i=1,...,n.
			agentStep3[i] = inquirerStep2.subtract(RN[i]);
			//Then the agent applies the decryption function K- to each of the n terms K+(IRN)+RN[k]-RN[i].
			agentStep3[i] = RSA.decrypt(privateKey, modulus, agentStep3[i]);
			//And adds I[i] to each corresponding ith outcome of applying the decryption function: K-(K+(IRN)+RN[k]-RN[i])+I[i].
			agentStep3[i] = agentStep3[i].add(BigInteger.valueOf((int)I[i]));
			//Finally, note also that without knowing IRN, the agent could not know the specific kth item the inquirer is asking.
		}

		System.out.println("Send K-(K+(IRN)+RN[k]-RN[i])+I[i] for i=1,...,n to inquirer.");
		
		output.writeObject(agentStep3);
		output.flush();

		input.close(); 
		output.close(); 
		socket.close();
		server.close();
	}
}