/**
 * @author Jasminder Garcha
 */
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Base64;


//RSA based 1-n Oblivious Transfer Protocol simulator.
//I/O: ObjectInputStream/ObjectOutputStream.
//Inquirer.
public class Inquirer {
	private int k;
	private Object informationItem;

	public Inquirer() {
		k = -1;
	}

	public Inquirer(int informationItemIndex) {
		k = informationItemIndex;
	}

	public void setK(int informationItemIndex) {
		k = informationItemIndex;
	}

	public int getK() {
		return k;
	}
	
	public Object getInformationItem() {
		return informationItem;
	}

	public void setInformationItem(Object informationObject) {
		informationItem = informationObject;
	}

	public static void main(String[] args) throws Exception {
		Socket socket = new Socket("localhost", 381); //Connect to Agent.
		ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
		ObjectInputStream input = new ObjectInputStream(socket.getInputStream()); 		

		SecureRandom random = new SecureRandom();

		int numberOfInformationItems = input.readInt(); //n.

		int informationItemIndex = random.nextInt(numberOfInformationItems); //k.

		Inquirer inquirer = new Inquirer();		
		inquirer.setK(informationItemIndex);

		int k = inquirer.getK();	

		System.out.println("Sending k="+k+" to agent.\n");
		
		output.writeInt(k);
		output.flush();

		System.out.println("Receiving public key from agent.");

		BigInteger publicKey = (BigInteger)input.readObject(); 

		System.out.println(Base64.getEncoder().encodeToString(publicKey.toByteArray())+"\n");

		BigInteger modulus = (BigInteger)input.readObject();

		System.out.println("Receiving random numbers RN[1],...,RN[n] from agent.");

		BigInteger[] RN = (BigInteger[])input.readObject(); //RN[1],...,RN[n].

		for(int i = 0; i < RN.length; i++) {
			System.out.println("RN["+i+"]="+RN[i]);
		}
		System.out.println();

		BigInteger IRN = new BigInteger(32, random); //Inquirer random number.

		//Step 2: Inquirer sends K+(IRN)+RN[k] to agent.
		BigInteger inquirerStep2 = RSA.encrypt(publicKey, modulus, IRN).add(RN[k]);

		System.out.println("Send K+(IRN)+RN[k] to agent.\n");
		
		output.writeObject(inquirerStep2);
		output.flush();
		
		System.out.println("Receive K-(K+(IRN)+RN[k]-RN[i])+I[i] for i=1,...,n from agent.");
		
		BigInteger[] agentStep3 = (BigInteger[])input.readObject(); 

		//Step 4: Inquirer offsets the kth terms sent by the agent in step 3 with IRN: K-(K+(IRN)+RN[k]-RN[i])+I[i]
		BigInteger[] inquirerStep4 = new BigInteger[agentStep3.length];
		for(int i = 0; i < inquirerStep4.length; i++) {
			inquirerStep4[i] = 	agentStep3[i].subtract(IRN);
			System.out.println("Term "+i+": "+inquirerStep4[i]);
		}
		System.out.println();

		Object informationItem = inquirerStep4[k];
		inquirer.setInformationItem(informationItem);
		
		System.out.println("Information item: "+inquirer.getInformationItem());
		
		/* When i != k, K-(K+(IRN)+RN[k]-RN[i]) is a value unknown to the inquirer as the inquirer does not	know the decryption secret of the agent. 
		 * Thus, the inquirer could not derive the correct value of I[i] when i != k. 
		 * In other	words, at the end of the process the inquirer will know only exactly I[k] but nothing else.
		 */
		
		input.close(); 
		output.close(); 
		socket.close(); 
	}
}