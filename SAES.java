/*
Programming Problem 6.14 -

Simplified AES implementation
16 bit plain text and 16 bit key preferred
*/



import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

import java.util.Arrays;

class SAES
{
	public static String[][] sBox = {{"1001","0100","1010","1011"},{"1101","0001","1000","0101"},{"0110","0010","0000","0011"},{"1100","1110","1111","0111"}};
	public static String[][] inverseSBox = {{"1010","0101","1001","1011"},{"0001","0111","1000","1111"},{"0110","0000","0010","0011"},{"1100","0100","1101","1110"}};
	public static int length = 16, blockSize = 4;
	public static void main(String[] args)throws IOException
	{
		int i = 0, j = 0, x = 0, k = 0, ind = 0, rotateLength = 0, inverseRotateLength = 0;//, temp = 0;
		//char[] readData = null;
		String readData = null;
		x = (int)Math.sqrt(length/blockSize);
		char[][][] plainText = new char[x][x][blockSize], cipherText = new char[x][x][blockSize], key0 = new char[x][x][blockSize], key1 = new char[x][x][blockSize], key2 = new char[x][x][blockSize];
		int[] sBoxIndices = new int[2];
		char[] temp;

		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Enter the plaintext-");
		readData = reader.readLine();//.toCharArray();
		for (i = 0; i < x; ++i)
			for (j = 0; j < x; ++j)
				for (k = 0; k < blockSize; ++k)
					plainText[j][i][k] = readData.charAt(ind++);
		ind = 0;
		System.out.println("Enter the key-");
		readData = reader.readLine();//.toCharArray();
		for (i = 0; i < x; ++i)
			for (j = 0; j < x; ++j)
				for (k = 0; k < blockSize; ++k)
					key0[j][i][k] = readData.charAt(ind++);
		ind = 0;

		//generate two new keys
		key1 = generateNewKey(key0,new char[][]{{'1','0','0','0'},{'0','0','0','0'}});
		key2 = generateNewKey(key1,new char[][]{{'0','0','1','1'},{'0','0','0','0'}});

		System.out.println("------------------------------------------------------------------");
		System.out.println("                         Given Plain Text");
		System.out.println("------------------------------------------------------------------");
		for (i = 0; i < x; ++i)
		{
			for (j = 0; j < x; ++j)
			{
				for (k = 0; k < blockSize; ++k)
					System.out.print(plainText[j][i][k]);
				System.out.print(" ");
			}
			System.out.print(" ");
		}
		System.out.println();
		System.out.println();

		//////////////////////////////////////////////////////////////////////////
		//								ENCRYPTION
		//////////////////////////////////////////////////////////////////////////
		
		//XOR with key0
		cipherText = performXor(plainText,key0);

		//Nibble Substitution
		for (i = 0; i < x; ++i)
		{
			for (j = 0; j < x; ++j)
			{
				sBoxIndices = getSBoxIndices(cipherText[i][j]);
				cipherText[i][j] = sBox[sBoxIndices[0]][sBoxIndices[1]].toCharArray();
			}
		}

		//Shift rows
		for (k = 1; k < x; ++k)
		{
			++rotateLength;
	        for (i = 0, j = rotateLength-1; i < j; ++i, --j)
	        {
	            temp = cipherText[k][i];
	            cipherText[k][i] = cipherText[k][j];
	            cipherText[k][j] = temp;
	        }
	        
	        for (i = rotateLength, j = x-1; i < j; ++i, --j)
	        {
	            temp = cipherText[k][i];
	            cipherText[k][i] = cipherText[k][j];
	            cipherText[k][j] = temp;
	        }
	        
	        for (i = 0, j = x-1; i < j; ++i, --j)
	        {
	            temp = cipherText[k][i];
	            cipherText[k][i] = cipherText[k][j];
	            cipherText[k][j] = temp;
	        }
		}
		rotateLength = 0;
		
		//Mix columns
		/*    b            c
		-----------------------
		      j0           j1
		i0  0 1 2 3     0 1 2 3
		i1  4 5 6 7     4 5 6 7*/
		for (i = 0; i < x; ++i)
			for (j = 0; j < x; ++j)
				for (k = 0; k < blockSize; ++k)
					plainText[i][j][k] = cipherText[i][j][k];
		for (i = 0; i < x; ++i)
		{
			cipherText[0][i][0] = performXor(plainText[0][i][0],plainText[1][i][2]);
			cipherText[0][i][1] = performXor(plainText[0][i][1],plainText[1][i][0],plainText[1][i][3]);
			cipherText[0][i][2] = performXor(plainText[0][i][2],plainText[1][i][0],plainText[1][i][1]);
			cipherText[0][i][3] = performXor(plainText[0][i][3],plainText[1][i][1]);
			cipherText[1][i][0] = performXor(plainText[0][i][2],plainText[1][i][0]);
			cipherText[1][i][1] = performXor(plainText[0][i][0],plainText[0][i][3],plainText[1][i][1]);
			cipherText[1][i][2] = performXor(plainText[0][i][0],plainText[0][i][1],plainText[1][i][2]);
			cipherText[1][i][3] = performXor(plainText[0][i][1],plainText[1][i][3]);
		}

		//XOR with key1
		cipherText = performXor(cipherText,key1);

		//Nibble substituion round-2
		for (i = 0; i < x; ++i)
		{
			for (j = 0; j < x; ++j)
			{
				sBoxIndices = getSBoxIndices(cipherText[i][j]);
				cipherText[i][j] = sBox[sBoxIndices[0]][sBoxIndices[1]].toCharArray();
			}
		}

		//Shift rows round-2
		for (k = 1; k < x; ++k)
		{
			++rotateLength;
	        for (i = 0, j = rotateLength-1; i < j; ++i, --j)
	        {
	            temp = cipherText[k][i];
	            cipherText[k][i] = cipherText[k][j];
	            cipherText[k][j] = temp;
	        }
	        
	        for (i = rotateLength, j = x-1; i < j; ++i, --j)
	        {
	            temp = cipherText[k][i];
	            cipherText[k][i] = cipherText[k][j];
	            cipherText[k][j] = temp;
	        }
	        
	        for (i = 0, j = x-1; i < j; ++i, --j)
	        {
	            temp = cipherText[k][i];
	            cipherText[k][i] = cipherText[k][j];
	            cipherText[k][j] = temp;
	        }
		}
		rotateLength = 0;

		//XOR with key2
		cipherText = performXor(cipherText,key2);
				
		System.out.println("------------------------------------------------------------------");
		System.out.println("                   Cipher Text (After Encryption)");
		System.out.println("------------------------------------------------------------------");
		for (i = 0; i < x; ++i)
		{
			for (j = 0; j < x; ++j)
			{
				for (k = 0; k < blockSize; ++k)
					System.out.print(cipherText[j][i][k]);
				System.out.print(" ");
			}
			System.out.print(" ");
		}
		System.out.println();
		System.out.println();

		//////////////////////////////////////////////////////////////////////////
		//								DECRYPTION
		//////////////////////////////////////////////////////////////////////////

		//XOR with key2
		plainText = performXor(cipherText,key2);

		//Inverse Shift rows
		for (k = 1; k < x; ++k)
		{
			++rotateLength;
			inverseRotateLength = x-rotateLength;
	        for (i = 0, j = inverseRotateLength-1; i < j; ++i, --j)
	        {
	            temp = plainText[k][i];
	            plainText[k][i] = plainText[k][j];
	            plainText[k][j] = temp;
	        }
	        
	        for (i = inverseRotateLength, j = x-1; i < j; ++i, --j)
	        {
	            temp = plainText[k][i];
	            plainText[k][i] = plainText[k][j];
	            plainText[k][j] = temp;
	        }
	        
	        for (i = 0, j = x-1; i < j; ++i, --j)
	        {
	            temp = plainText[k][i];
	            plainText[k][i] = plainText[k][j];
	            plainText[k][j] = temp;
	        }
		}
		rotateLength = 0;

		//Inverse Nibble substitution
		for (i = 0; i < x; ++i)
		{
			for (j = 0; j < x; ++j)
			{
				sBoxIndices = getSBoxIndices(plainText[i][j]);
				plainText[i][j] = inverseSBox[sBoxIndices[0]][sBoxIndices[1]].toCharArray();
			}
		}

		//XOR with key1
		plainText = performXor(plainText,key1);

		//Inverse Mix Columns
		/*    k            l
		-----------------------
		      j0           j1
		i0  0 1 2 3     0 1 2 3
		i1  4 5 6 7     4 5 6 7*/
		for (i = 0; i < x; ++i)
			for (j = 0; j < x; ++j)
				for (k = 0; k < blockSize; ++k)
					cipherText[i][j][k] = plainText[i][j][k];
		for (i = 0; i < x; ++i)
		{
			plainText[0][i][0] = performXor(cipherText[0][i][3],cipherText[1][i][1]);
			plainText[0][i][1] = performXor(cipherText[0][i][0],cipherText[1][i][2]);
			plainText[0][i][2] = performXor(cipherText[0][i][1],cipherText[1][i][0],cipherText[1][i][3]);
			plainText[0][i][3] = performXor(cipherText[0][i][2],cipherText[0][i][3],cipherText[1][i][1]);
			plainText[1][i][0] = performXor(cipherText[0][i][1],cipherText[1][i][3]);
			plainText[1][i][1] = performXor(cipherText[0][i][2],cipherText[1][i][0]);
			plainText[1][i][2] = performXor(cipherText[0][i][0],cipherText[0][i][3],cipherText[1][i][1]);
			plainText[1][i][3] = performXor(cipherText[0][i][0],cipherText[1][i][2],cipherText[1][i][3]);
		}

		//Inverse Shift rows round-2
		for (k = 1; k < x; ++k)
		{
			++rotateLength;
			inverseRotateLength = x-rotateLength;
	        for (i = 0, j = inverseRotateLength-1; i < j; ++i, --j)
	        {
	            temp = plainText[k][i];
	            plainText[k][i] = plainText[k][j];
	            plainText[k][j] = temp;
	        }
	        
	        for (i = inverseRotateLength, j = x-1; i < j; ++i, --j)
	        {
	            temp = plainText[k][i];
	            plainText[k][i] = plainText[k][j];
	            plainText[k][j] = temp;
	        }
	        
	        for (i = 0, j = x-1; i < j; ++i, --j)
	        {
	            temp = plainText[k][i];
	            plainText[k][i] = plainText[k][j];
	            plainText[k][j] = temp;
	        }
		}

		//Inverse Nibble substitution round-2
		for (i = 0; i < x; ++i)
		{
			for (j = 0; j < x; ++j)
			{
				sBoxIndices = getSBoxIndices(plainText[i][j]);
				plainText[i][j] = inverseSBox[sBoxIndices[0]][sBoxIndices[1]].toCharArray();
			}
		}

		//XOR with key0
		plainText = performXor(plainText,key0);

		System.out.println("------------------------------------------------------------------");
		System.out.println("                   Plain Text (After Decryption)");
		System.out.println("------------------------------------------------------------------");
		for (i = 0; i < x; ++i)
		{
			for (j = 0; j < x; ++j)
			{
				for (k = 0; k < blockSize; ++k)
					System.out.print(plainText[j][i][k]);
				System.out.print(" ");
			}
			System.out.print(" ");
		}
		System.out.println();
		System.out.println();
	}

	public static char[][][] generateNewKey(char[][][] key, char[][] roundKey)
	{
		int x = (int)Math.sqrt(length/blockSize), i = 0, j = 0;
		char[][][] newKey = new char[x][x][blockSize];
		char[][] w0 = new char[x][blockSize];
		char[][] w1 = new char[x][blockSize];
		char[][] w2 = new char[x][blockSize];
		char[][] w3 = new char[x][blockSize];
		
		//store w0
		for (i = 0; i < x; ++i)
			for (j = 0; j < blockSize; ++j)
				w0[i][j] = key[i][0][j];

		//store w1
		for (i = 0; i < x; ++i)
			for (j = 0; j < blockSize; ++j)
				w1[i][j] = key[i][1][j];

		//step-1 swap two blocks
		int r1 = 0, r2 = 1;
		for (i = 0; i < blockSize; ++i)
			w2[r1][i] = key[r2][1][i];
		r1 = 1;
		r2 = 0;
		for (i = 0; i < blockSize; ++i)
			w2[r1][i] = key[r2][1][i];

		//substitution
		int[] indices;
		for (i = 0; i < x; ++i)
		{
			indices = getSBoxIndices(w2[i]);
			w2[i] = sBox[indices[0]][indices[1]].toCharArray();
		}

		//XOR round key
		w2 = performXor(w2,roundKey);

		//XOR with w0
		w2 = performXor(w0,w2); //this gives w2
		for (i = 0; i < x; ++i)
			for (j = 0; j < blockSize; ++j)
				newKey[i][0][j] = w2[i][j];

		//XOR with w1
		w3 = performXor(w1,w2); //this gives w3

		for (i = 0; i < x; ++i)
			for (j = 0; j < blockSize; ++j)
				newKey[i][1][j] = w3[i][j];

		return newKey;
	}

	public static int[] getSBoxIndices(char[] block)
	{
		int[] indices = new int[2];
		if (block[0] == '0' && block[1] == '0') indices[0] = 0;
		else if (block[0] == '0' && block[1] == '1') indices[0] = 1;
		else if (block[0] == '1' && block[1] == '0') indices[0] = 2;
		else if (block[0] == '1' && block[1] == '1') indices[0] = 3;
		if (block[2] == '0' && block[3] == '0') indices[1] = 0;
		else if (block[2] == '0' && block[3] == '1') indices[1] = 1;
		else if (block[2] == '1' && block[3] == '0') indices[1] = 2;
		else if (block[2] == '1' && block[3] == '1') indices[1] = 3;
		return indices;
	}

	public static char performXor(char ch1, char ch2)
	{
		if (ch1 == ch2) return '0';
		return '1';
	}

	public static char performXor(char ch1, char ch2, char ch3)
	{
		if (ch1 == ch2)
		{
			if (ch2 == ch3) return ch1;
			else return ch3;
		}
		return ch3 == '0' ? '1' : '0';
	}

	public static char[][] performXor(char[][] data1, char[][] data2)
	{
		char[][] result = new char[data1.length][data1[0].length];
		int i = 0, j = 0;
		for (i = 0; i < data1.length; ++i)
		{
			for (j = 0; j < data1[0].length; ++j)
			{
				if (data1[i][j] == data2[i][j]) result[i][j] = '0';
				else result[i][j] = '1';
			}
		}
		return result;
	}

	public static char[][][] performXor(char[][][] data1, char[][][] data2)
	{
		char[][][] result = new char[data1.length][data1[0].length][data1[0][0].length];
		int i = 0, j = 0, k = 0;
		for (i = 0; i < data1.length; ++i)
		{
			for (j = 0; j < data1[0].length; ++j)
			{
				for (k = 0; k < data1[0][0].length; ++k)
				{
					if (data1[i][j][k] == data2[i][j][k]) result[i][j][k] = '0';
					else result[i][j][k] = '1';
				}
			}
		}
		return result;
	}
}