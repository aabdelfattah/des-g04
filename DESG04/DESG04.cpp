#include <stdio.h>
#include <stdlib.h>
#include "string.h"
#include "time.h"
#include "conio.h"

///////////////////////////////////////////
// Macros that we used in bit masking
#define bit_get(p,m) ((p) & (m)) 
#define bit_set(p,m) ((p) |= (m)) 
#define bit_clear(p,m) ((p) &= ~(m)) 
#define bit_flip(p,m) ((p) ^= (m)) 
#define bit_write(c,p,m) (c ? bit_set(p,m) : bit_clear(p,m)) 
#define BIT(x) (0x01 << (x)) 
#define LONGBIT_64(x) ((long long)0x0000000000000001 << (x))
#define LONGBIT_32(x) ((long long)0x00000001 << (x))
#define LONGBIT_64_6(x) ((long long)0x000000000000003f << (x))
///////////////////////////////////////////////////////////////////
/// Tables used in DES

//#define bit_shift(p,m) ()



//Edit : Why short ???
short Sbox [8][4][16] ={ { 
		  { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 },
          {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
          {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
		  { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 }},

        { { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
          {  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
          {  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
          { 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 }
        },

        { { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
          { 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
          { 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
          {  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 }
        },

        { {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
          { 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
          { 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
          {  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 }
        },

        { {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
          { 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
          {  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
          { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 }
        },

        { { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
          { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 },
          {  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6 },
          {  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 }
        },

        { {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
          { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
          {  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
          {  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 }
        },

        { { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
          {  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
          {  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
          {  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
        }
};


static int initial_perm[64] = { 
	58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15, 7
};

	static int pc1[56] = 
{ 
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

static int rots[16] = { 
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 
};

	
static int pc2[48] = { 
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};


static int expansion[48] = 
	{ 
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
    };

static int permutationAfterS[32] = {
  16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
  2,   8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

static int final_perm[64] = {
  40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
  38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
  36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
  34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25
};




bool LoadKey(FILE* pKeyFile , long long *key64bit )
{
	int temp ;
	char c ;
	int counter = 4 ;
	
	for( int i = 0 ; i < 23 ; i++ )
	{
		fscanf(pKeyFile,"%c",&c);
		switch (c)
		{
			case ' ' :
				counter = counter - 4 ;
				break ;
			case 'a' :
			case 'A' :
				
				*key64bit |= ((long long) 10<<(64-counter));
				break ;
			case 'b' :
			case 'B' :
	
				*key64bit |= ((long long) 11<<(64-counter));
				break ;
			case 'c' :
			case 'C' :
	
				*key64bit |= ((long long) 12<<(64-counter));
				break ;
			case 'd' :
			case 'D' :
				
				*key64bit |= ((long long) 13<<(64-counter));
				break ;
			case 'e' :
			case 'E' :
				
				*key64bit |= ((long long) 14<<(64-counter));
				break ;
			case 'f' :
			case 'F' :
			
				*key64bit |= ((long long) 15<<(64-counter));
				break ; 
			default :
				c = c-'0';
				*key64bit |= ((long long) c<<(64-counter));	
				break ;
				
		}
		counter += 4 ;

	}	
	return true ;
}



bool Load64Bit2(FILE* pKeyFile , long long * Data64Bit, int completeBlockCount,int uncompleteByte,int bytesToStuff,int* count)
{
	int x = 1;
	char data[8] ;

	if(*count <= completeBlockCount){
		x = fread(data,sizeof(data),1,pKeyFile);
			if(x!=1)
			
			return false;
			*Data64Bit = ( (((long long )data[0] << 56)&(0xFF00000000000000))|
						   (((long long )data[1] << 48)&(0x00FF000000000000))| 
						   (((long long )data[2] << 40)&(0x0000FF0000000000))|
						   (((long long )data[3] << 32)&(0x000000FF00000000))|
						   (((long long )data[4] << 24)&(0x00000000FF000000))|
						   (((long long )data[5] << 16)&(0x0000000000FF0000))|
						   (((long long )data[6] << 8 )&(0x000000000000FF00))|
						   (((long long )data[7] )     &(0x00000000000000FF))
						 ) ;
			*count = *count + 1  ;
	}
	else if(*count == completeBlockCount+1)
	{

		x = fread(data,uncompleteByte,1,pKeyFile);
			if(x!=1)
			
			return false;
			for (int i = uncompleteByte ; i < 8 ; i++  )
			{
				data[i]=bytesToStuff;
			}
			*Data64Bit = ( (((long long )data[0] << 56)&(0xFF00000000000000))|
						   (((long long )data[1] << 48)&(0x00FF000000000000))| 
						   (((long long )data[2] << 40)&(0x0000FF0000000000))|
						   (((long long )data[3] << 32)&(0x000000FF00000000))|
						   (((long long )data[4] << 24)&(0x00000000FF000000))|
						   (((long long )data[5] << 16)&(0x0000000000FF0000))|
						   (((long long )data[6] << 8 )&(0x000000000000FF00))|
						   (((long long )data[7] )     &(0x00000000000000FF))
						 ) ;
			*count = *count + 1  ;
	}
	else 
	{
		return false ;
	}
			
	

		
		return true;
}

bool Load64Bit1(FILE* pKeyFile , long long * Data64Bit )
{
	

	int x = 1;
	char data[8] ;
	
	
		x = fread(data,sizeof(data),1,pKeyFile);
		if(x!=1)
		return false;
		*Data64Bit = ( (((long long )data[0] << 56)&(0xFF00000000000000))|
					   (((long long )data[1] << 48)&(0x00FF000000000000))| 
					   (((long long )data[2] << 40)&(0x0000FF0000000000))|
					   (((long long )data[3] << 32)&(0x000000FF00000000))|
					   (((long long )data[4] << 24)&(0x00000000FF000000))|
					   (((long long )data[5] << 16)&(0x0000000000FF0000))|
					   (((long long )data[6] << 8 )&(0x000000000000FF00))|
					   (((long long )data[7] )     &(0x00000000000000FF)) );
		
	

		return true;
}

bool Write64Bit(FILE* pKeyFile , long long * Data64Bit )
{
	
	//int *firstHalf = 0;
	//int *secondHalf=0;
	int x = 1;
	char data[8] ;
	char c = '0' ; 
	
	data[0] = (char) (*Data64Bit >> 56); 
	data[1] = (char) (*Data64Bit >> 48);
	data[2] = (char) (*Data64Bit >>40 );
	data[3] = (char) (*Data64Bit  >> 32);
	data[4] = (char) (*Data64Bit >> 24); 
	data[5] = (char) (*Data64Bit >> 16);
	data[6] = (char) (*Data64Bit >>8);
	data[7] = (char) (*Data64Bit)  ;
	x = fwrite(data,sizeof(data),1,pKeyFile);
	if(x!=1)
		return false;
	
	return true;
}

void getKeyArray(long long key_56 , long long *key_48)
{
	long long keyShifted_56=0;
	
	for(int key48Counter=0;key48Counter<16;key48Counter++)
	{
		//LEFT SHIFTING
		for(int keyShiftCounter=0;keyShiftCounter<rots[key48Counter];keyShiftCounter++)//Either one Shift or two Shifts
			{
			key_56 = key_56<<1;// shift left by one	
			bit_write(bit_get(key_56,LONGBIT_64(28)),key_56,LONGBIT_64(0));	// move bit 28 to bit# zero
			bit_write(bit_get(key_56,LONGBIT_64(56)),key_56,LONGBIT_64(28));//move bit 56 to bit# 28
			bit_clear(key_56,LONGBIT_64(56));//clear bit 56 as key should be from 0-55
			}
		key_48[key48Counter]=0;
		//keyShifted_56=0x00e19955faaccf1e;// for testing
		keyShifted_56=key_56;
		for(int pC2Counter=0;pC2Counter<48;pC2Counter++)
			{
			// First of all u need to understand bit_get,, 
			//	c: the value of the bit which we write,,(for ex : in the  table(first bit comes from bit# 57),,
			//	if bit# 57 is 0 we write zero to the first bit in the output else we write 1
			//	P: the 56bit output which resulted from permuted choice "Destination"
			//	m: is the mask (position) of the bit_in_the output "KEY"     
			
			// key_64 = ((_int64)key_56High << 32) | key_56Low; uncomment this Line if the data input is 2 32-register 
	
			bit_write(bit_get(keyShifted_56,LONGBIT_64(56-pc2[pC2Counter])),
			key_48[key48Counter],
			LONGBIT_64(48-pC2Counter-1));												
			}
	
	}
}

void expansionPermutation(long rightData , long long *rDataAfterExpansion)
{
	for(int expCounter=0 ; expCounter<48 ; expCounter++)
		{
		bit_write(bit_get(rightData,LONGBIT_64(32-expansion[expCounter])),
					*rDataAfterExpansion,
					LONGBIT_64(47-expCounter));

		}
					
}

long long sBox(long long rDataAfterExpansion)
{
	long long input= 0;
	long long output = 0;
	long long  frame=0;
	short row=0;
	short column=0;
	int bit_num;
	input=rDataAfterExpansion;
	for(int s=0;s<8;s++)  
	{
		frame = 0;
		frame  = input & LONGBIT_64_6(s*6); // Fetching the frame 
		frame = frame>>(s*6);
		
		if(frame%2 == 0) // if the frame contain even number
		{
			if(frame <32)
			{
				row = 0;
				column = frame/2;
			}
			else if(frame >= 32)
			{
				row = 2;
				column = (frame-32)/2;
			}
		}
		else                          // if the frame contain odd number 
		{
			if(frame <33)
			{
				row = 1;
				column = frame/2;
			}
			else if(frame >= 33)
			{
				row = 3;
				column = (frame-32)/2;
			}
		}
	/////////////// assgning values into output ///////////////////////
	output |= Sbox[7-s][row][column]<<(4*s);
		
}
	return output;

}

bool Write64Bit2(FILE* pKeyFile , long long * Data64Bit, int completeBlockCount,int* count )
{
	int x = 1;
	char data[8] ;
	int byteToStuff;
	char c = '0' ; 
	data[0] = (char) (*Data64Bit >> 56); 
	data[1] = (char) (*Data64Bit >> 48);
	data[2] = (char) (*Data64Bit >> 40 );
	data[3] = (char) (*Data64Bit  >> 32);
	data[4] = (char) (*Data64Bit >> 24); 
	data[5] = (char) (*Data64Bit >> 16);
	data[6] = (char) (*Data64Bit >>8);
	data[7] = (char) (*Data64Bit)  ;
	if(*count < completeBlockCount)
	{
		x = fwrite(data,sizeof(data),1,pKeyFile);
		if(x!=1)
			return false;
		*count =*count + 1  ;
	}
	else if (*count == completeBlockCount)
	{
		byteToStuff=(int)data[7];
		for(int p=0;p<(8-byteToStuff);p++)
		{
		x = fwrite(&data[p],1,1,pKeyFile);
		if(x!=1)
			return false;
		}
			*count =*count + 1  ;
	}
	else 
	{
		return false ;
	}
	return true;
}

int main (int argc, char *argv[])
{
	long startTime = clock();
	
	//Remove this comment at the latest stage of the program
	if((argc-1)!=4)
	{
		printf("\nInvalid Program Arguments.\n");
		return 0;
	}
	
	//////////////////////////////////////////////////////////////////////////////

	

	////////////////////////////////////////////////////////////////////////////////
	// open files and check that they exist
	FILE* plainTextFile = 0;
	FILE* pCipherTextFile = 0;
	FILE* keyFile = 0;
	keyFile = fopen((const char*)argv[3] , "r");
	if(keyFile==0)
		{
			printf("Error opening key file.");
			return 0;
		}
	///////////////////////////////////////////////////////////////////////////////


	//////////////////////////////////////////////////////////////////////////////////////////
	// key code (get keys for 16 round key_48[i] where i=0----->16)

	
	
	////////////////////////////////////////////////////////////////////////////////////////
	///First Permutation Choice OF Key_64
	long long key_64,key_56;
	
	key_56=0;
	key_64=0;
	
	LoadKey(keyFile,&key_64);

	

	for(int key56Counter=0;key56Counter<56;key56Counter++)
	{
		/* First of all u need to understand bit_get,, 
			c: the value of the bit which we write,,(for ex : in the  table(first bit comes from bit# 57),,
			if bit# 57 is 0 we write zero to the first bit in the output else we write 1
			P: the 56bit output which resulted from permuted choice "Destination"
			m: is the mask (position) of the bit_in_the output "KEY"     
		*/
		bit_write(
			bit_get(key_64,LONGBIT_64(64-pc1[key56Counter])),
			key_56,
			LONGBIT_64(56-key56Counter-1));												
	}


	
	/////////////////////////////////////////////////////////////////////////////////////
	//shifting the key and PC2 
	/*
	long long keyShifted_56;
	
	keyShifted_56=0;
*/
	long long key_48[16];
	getKeyArray(key_56 , key_48);
/*
	for(int key48Counter=0;key48Counter<16;key48Counter++)
	{
		//LEFT SHIFTING
		for(int keyShiftCounter=0;keyShiftCounter<rots[key48Counter];keyShiftCounter++)//Either one Shift or two Shifts
			{
			key_56 = key_56<<1;// shift left by one	
			bit_write(bit_get(key_56,LONGBIT_64(28)),key_56,LONGBIT_64(0));	// move bit 28 to bit# zero
			bit_write(bit_get(key_56,LONGBIT_64(56)),key_56,LONGBIT_64(28));//move bit 56 to bit# 28
			bit_clear(key_56,LONGBIT_64(56));//clear bit 56 as key should be from 0-55
			}
		key_48[key48Counter]=0;
		//keyShifted_56=0x00e19955faaccf1e;// for testing
		keyShifted_56=key_56;
		for(int pC2Counter=0;pC2Counter<48;pC2Counter++)
			{
			// First of all u need to understand bit_get,, 
			//	c: the value of the bit which we write,,(for ex : in the  table(first bit comes from bit# 57),,
			//	if bit# 57 is 0 we write zero to the first bit in the output else we write 1
			//	P: the 56bit output which resulted from permuted choice "Destination"
			//	m: is the mask (position) of the bit_in_the output "KEY"     
			
			// key_64 = ((_int64)key_56High << 32) | key_56Low; uncomment this Line if the data input is 2 32-register 
	
			bit_write(bit_get(keyShifted_56,LONGBIT_64(56-pc2[pC2Counter])),
			key_48[key48Counter],
			LONGBIT_64(48-pC2Counter-1));												
			}
	
	}
*/
	///////////////Encryption////////////////////////////////////////////////////////////////////////////////////////////////////////
	int fileLength ;
	int completeBlockCount; 
	int uncompleteByte; 
	int bytesToStuff ;

	int count;
	if(stricmp(argv[1], "encrypt")==0)
	{


		
		plainTextFile = fopen((const char*)argv[2], "rb");

		pCipherTextFile = fopen((const char*)argv[4], "wb");
		
		
		
		if(plainTextFile==0)
		{
			printf("Error opening plaintext file.");
			return 0;
		}
		if(pCipherTextFile==0)
		{
			printf("Error opening cipher file.");
			return 0;
		}
		
		printf("\n >>Encryption in progress");
		/////////////////////////////////////////////////
						
		fseek(plainTextFile, 0, SEEK_END);//pointer to the file  that required to know its lenght
		fileLength = ftell(plainTextFile);//tell the size of the file
		completeBlockCount = fileLength / 8 ;
		uncompleteByte = fileLength % 8 ;
		bytesToStuff = (8-(fileLength%8)); //see how many char is missing to make it divisable by 8 (padding) 
		fseek(plainTextFile, 0, SEEK_SET);//return the pionter to the begining of the file
		count=1;
		//////////////////////////////

		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		/// variable declaration 
		
		bool readingOk = true;
		long long data64Bit =0;
		long long dataAfterIP,dataBeforeIP = 0;
		long long rDataAfterExpansion;
		long rightData , leftData ;
		int expCounter ;
		long sOutput ;			
		long  xorInput;
		int iPCounter;
		int roundCounter;
		int perm32Counter ;
		long long temp; //////change the name to exchange right and left data

		/////////////////////////////////////////////////////////////////////////////////
		/// Encryption code

		//////////////////////////////////////////////////
		//Will keep reading data until EOF is returned (b is false)
		while(Load64Bit2(plainTextFile,&dataBeforeIP,completeBlockCount,uncompleteByte,bytesToStuff,&count))
		{
			////////////////////////////////////////////////////////////////////////
			//initial permutation
		
			dataAfterIP=0;

			////////////////////////////////////////////////////////////////////////////////
			dataAfterIP|= ((dataBeforeIP&0x0000040000200000))<<0;
			dataAfterIP|= ((dataBeforeIP&0x0040000100000800))<<3;
			dataAfterIP|= ((dataBeforeIP&0x0000100000800002))<<6;
			dataAfterIP|= ((dataBeforeIP&0x0000000400002000))<<9;
			dataAfterIP|= ((dataBeforeIP&0x0000400001000008))<<12;
			dataAfterIP|= ((dataBeforeIP&0x0000001000008000))<<15;
			dataAfterIP|= ((dataBeforeIP&0x0000000004000020))<<18;
			dataAfterIP|= ((dataBeforeIP&0x0000004000010000))<<21;
			dataAfterIP|= ((dataBeforeIP&0x0000000010000080))<<24;
			dataAfterIP|= ((dataBeforeIP&0x0000000000040000))<<27;
			dataAfterIP|= ((dataBeforeIP&0x0000000040000100))<<30;
			dataAfterIP|= ((dataBeforeIP&0x0000000000100000))<<33;
			dataAfterIP|= ((dataBeforeIP&0x0000000000000400))<<36;
			dataAfterIP|= ((dataBeforeIP&0x0000000000400001))<<39;
			dataAfterIP|= ((dataBeforeIP&0x0000000000001000))<<42;
			dataAfterIP|= ((dataBeforeIP&0x0000000000000004))<<45;
			dataAfterIP|= ((dataBeforeIP&0x0000000000004000))<<48;
			dataAfterIP|= ((dataBeforeIP&0x0000000000000010))<<51;
			dataAfterIP|= ((dataBeforeIP&0x0000000000000040))<<57;
			///////////////////////////////////////////////////////////////////////////
			dataAfterIP|= ((dataBeforeIP&0x0010000080000200))>>3;
			dataAfterIP|= ((dataBeforeIP&0x4000010000080000))>>6;
			dataAfterIP|= ((dataBeforeIP&0x0004000020000000))>>9;
			dataAfterIP|= ((dataBeforeIP&0x1000008000020000))>>12;
			dataAfterIP|= ((dataBeforeIP&0x0001000008000000))>>15;
			dataAfterIP|= ((dataBeforeIP&0x0400002000000000))>>18;
			dataAfterIP|= ((dataBeforeIP&0x0000800002000000))>>21;
			dataAfterIP|= ((dataBeforeIP&0x0100000800000000))>>24;
			dataAfterIP|= ((dataBeforeIP&0x0000200000000000))>>27;
			dataAfterIP|= ((dataBeforeIP&0x0080000200000000))>>30;
			dataAfterIP|= ((dataBeforeIP&0x0000080000000000))>>33;
			dataAfterIP|= ((dataBeforeIP&0x0020000000000000))>>36;
			dataAfterIP|= ((dataBeforeIP&0x8000020000000000))>>39;
			dataAfterIP|= ((dataBeforeIP&0x0008000000000000))>>42;
			dataAfterIP|= ((dataBeforeIP&0x2000000000000000))>>45;
			dataAfterIP|= ((dataBeforeIP&0x0002000000000000))>>48;
			dataAfterIP|= ((dataBeforeIP&0x0800000000000000))>>51;
			dataAfterIP|= ((dataBeforeIP&0x0200000000000000))>>57;

			///////////////////////////////////////////////////////////////////////////////////////////////////////
			//dividing data into right and left for the rounds

				rightData = dataAfterIP;
				leftData = dataAfterIP>>32;
	
			for( roundCounter =0 ;roundCounter< 16;roundCounter++)
				{
				////////////////////////////////////////////////////
				// expansion permutation

			
				rDataAfterExpansion = 0 ;
					rDataAfterExpansion|= ((long long)(rightData&0x00000001))<<47; // 0
					rDataAfterExpansion|= ((long long)(rightData&0xf8000000))<<15;   //1-5
					rDataAfterExpansion|= ((long long)(rightData&0x1f800000))<<13;   //4-9
					rDataAfterExpansion|= ((long long)(rightData&0x01f80000))<<11;   //8-13
					rDataAfterExpansion|= ((long long)(rightData&0x001f8000))<<9;   //12-17
					rDataAfterExpansion|= ((long long)(rightData&0x0001f800))<<7;   //16-21
					rDataAfterExpansion|= ((long long)(rightData&0x00001f80))<<5;   //20-25
					rDataAfterExpansion|= ((long long)(rightData&0x000001f8))<<3;  //24-29
					rDataAfterExpansion|= ((long long)(rightData&0x0000001f))<<01;  //28-32
					rDataAfterExpansion|= ((long long)(rightData&0x80000000))>>31;  //1 
					
				/////////////////////////////////////////////////////
				//xor  with the key
				rDataAfterExpansion^=key_48[roundCounter];

				////////////////////////////////////////////////////
				// S-box
					long long input= 0;
					long long output = 0;
					
					long long  frame=0;
					short row=0;
					short column=0;
					int bit_num;
					input=rDataAfterExpansion;
					//input=0x6117ba866527;//for testing
					//input=0x0c448deb63ec;//for testing
					//////////////////////////////////

					long long  input1=0;
					long long  input2=0;
					long long  input3=0;
					long long  input4=0;
					long long  input5=0;
					long long  input6=0;
					long long  input7=0;
					long long  input8=0;
	
					long long  output1=0;
					long long  output2=0;
					long long  output3=0;
					long long  output4=0;
					long long  output5=0;
					long long  output6=0;
					long long  output7=0;
					long long  output8=0;
				
					/////////////////////////////////////////////////////////////////////////
///////////////////// Fetching the 8 frames ////////////////////////////
	input1 = (input & LONGBIT_64_6(0));//& 0x000000000000003F; // least

	input2 = ((input & LONGBIT_64_6(6))>>6) ;//& 0x000000000000003F;

	input3 = ((input & LONGBIT_64_6(12))>>12) ;//& 0x000000000000003F;

	input4 = ((input & LONGBIT_64_6(18))>>18);// & 0x000000000000003F;

	input5 = ((input & LONGBIT_64_6(24))>>24) ;//& 0x000000000000003F;

	input6 = ((input & LONGBIT_64_6(30))>>30) ;//& 0x000000000000003F;

	input7 = ((input & LONGBIT_64_6(36))>>36) ;//& 0x000000000000003F;

	input8 = ((input & LONGBIT_64_6(42))>>42);// & 0x000000000000003F; // most
/////////////////////////////////////////// LUTs //////////////////////////////////
	switch (input8)
	{
		case 0 : {
					output1=14 ;
            		break;
				 }
		case 1 :
			{
				output1=0;
				break;
			}
		case 2 :
			{
				output1=4;
				break;
			}
		case 3 :
			{
				output1=15;
				break;
			}
		case 4 :
					
			{
				output1=13;
				break;
			}
		case 5:
			{
				output1=7;
				break;
			}
		case 6:
			{
				output1=1;
				break;
			}
		case 7:
			{
			    output1=4;
				break;
			}
		case 8:
			{
				output1=2;
				break;
			}
		case 9:
			{
				output1=14;
				break;
			}
		case 10:
			{
				output1=15;
				break;
			}
		case 11:
			{
				output1=2;
				break;
			}

		case 12:
			{
				output1=11;
				break;
			}
		case 13:
			{
				output1=13;
				break;
			}
		case 14:
			{
				output1=8;
				break;
			}
		case 15:
			{
				output1=1;
				break;
			}
		case 16:
			{
				output1=3;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output1=10;
				break;
			}
		case 18:
			{
				output1=10;
				break;
			}
		case 19:
			{
				output1=6;
				break;
			}
		case 20:
			{
				output1=6;
				break;

			}
		case 21:
			{
				output1=12;
				break;
			}
		case 22:
			{
				output1=12;
				break;
			}
		case 23:
			{
				output1=11;
				break;
			}
		case 24:
			{
				output1=5;
				break;
			}
		case 25:
			{
				output1=9;
				break;
			}
		case 26:
			{
				output1=9;
				break;

			}
		case 27:
			{
				output1=5;
				break;
			}
		case 28:
			{
				output1=0;
				break;
			}
		case 29:
			{
				output1=3;
				break;
			}
		case 30:
			{
				output1=7;
				break;
			}
		case 31:
			{
				output1=8;
				break;
			}
		case 32:
			{
				output1=4;
				break;
			}
		case 33:
			{
				output1=15;
				break;
			}
		case 34 :
			{
				output1=1;
				break;
			}
		case 35:
			{
				output1=12;
				break;
			}
		case 36:
			{
				output1=14;
				break;
			}
		case 37:
			{
				output1=8;
				break;
			}
		case 38:
			{
				output1=8;
				break;
			}
		case 39:
			{
				output1=2;
				break;
			}
		case 40:
			{
				output1=13;
				break;
			}
		case 41:
			{
				output1=4;
				break;
			}
		case 42:
			{
				output1=6;
				break;
			}
		case 43:
			{
				output1=9;
				break;
			}

		case 44:
			{
				output1=2;
				break;
			}
		case 45:
			{
				output1=1;
				break;
			}
		case 46:
			{
				output1=11;
				break;
			}
		case 47:
			{
				output1=7;
				break;
			}
		case 48:
			{
				output1=15;
				break;
			}
		case 49:
			{
				output1=5;
				break;
			}
		case 50:
			{
				output1=12;
				break;
			}
		case 51:
			{
				output1=11;
				break;
			}
		case 52:
			{
				output1=9;
				break;
			}
		case 53:
			{
				output1=3;///////////// wrong 8
				break;
			}
		case 54:
			{
				output1=7;
				break;
			}
		case 55:
			{
				output1=14;
				break;
			}
		case 56:
			{
				output1=3;
				break;
			}
		case 57:
			{
				output1=10;
				break;
			}
		case 58:
			{
				output1=10;
				break;
			}
		case 59:
			{
				output1=0;
				break;
			}
		case 60:
			{
				output1=5;
				break;
			}
		case 61:
			{
				output1=6;
				break;
			}
		case 62:
			{
				output1=0;
				break;
			}
		case 63:
			{
				output1=13;
				break;
			}

			} 


			///////////////////////////////////////////////////////////////////////////////////////
			//////////////////////////////input2///////////////////////////////////////////////////
			///////////////////////////////////////////////////////////////////////////////////////
			switch (input7)
			{
		case 0 : {
			output2=15;
            break;
				}
		case 1 :
			{
				output2=3;
				break;
			}
		case 2:
			{
				output2=1;
				break;
			}
		case 3 :
			{
				output2=13;
				break;
			}
		case 4 :
					
			{
				output2=8;
				break;
			}
		case 5:
			{
				output2=4;
				break;
			}
		case 6:
			{
				output2=14;
				break;
			}
		case 7:
			{
				output2=7;
				break;
			}
		case 8:
			{
				output2=6;
				break;
			}
		case 9:
			{
				output2=15;
				break;
			}
		case 10:
			{
				output2=11;
				break;
			}
		case 11:
			{
				output2=2;
				break;
			}

		case 12:
			{
				output2=3;
				break;
			}
		case 13:
			{
				output2=8;
				break;
			}
		case 14:
			{
				output2=4;
				break;
			}
		case 15:
			{
				output2=14;
				break;
			}
		case 16:
			{
				output2=9;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output2=12;
				break;
			}
		case 18:
			{
				output2=7;
				break;
			}
		case 19:
			{
				output2=0;
				break;
			}
		case 20:
			{
				output2=2;
				break;

			}
		case 21:
			{
				output2=1;
				break;
			}
		case 22:
			{
				output2=13;
				break;
			}
		case 23:
			{
				output2=10;
				break;
			}
		case 24:
			{
				output2=12;
				break;
			}
		case 25:
			{
				output2=6;
				break;
			}
		case 26:
			{
				output2=0;
				break;

			}
		case 27:
			{
				output2=9;
				break;
			}
		case 28:
			{
				output2=5;
				break;
			}
		case 29:
			{
				output2=11;
				break;
			}
		case 30:
			{
				output2=10;
				break;
			}
		case 31:
			{
				output2=5;
				break;
			}
		case 32:
			{
				output2=0;
				break;
			}
		case 33:
			{
				output2=13;
				break;
			}
		case 34 :
			{
				output2=14;
				break;
			}
		case 35:
			{
				output2=8;
				break;
			}
		case 36:
			{
				output2=7;
				break;
			}
		case 37:
			{
				output2=10;
				break;
			}
		case 38:
			{
				output2=11;
				break;
			}
		case 39:
			{
				output2=1;
				break;
			}
		case 40:
			{
				output2=10;
				break;
			}
		case 41:
			{
				output2=3;
				break;
			}
		case 42:
			{
				output2=4;
				break;
			}
		case 43:
			{
				output2=15;
				break;
			}

		case 44:
			{
				output2=13;
				break;
			}
		case 45:
			{
				output2=4;
				break;
			}
		case 46:
			{
				output2=1;
				break;
			}
		case 47:
			{
				output2=2;
				break;
			}
		case 48:
			{
				output2=5;
				break;
			}
		case 49:
			{
				output2=11;
				break;
			}
		case 50:
			{
				output2=8;
				break;
			}
		case 51:
			{
				output2=6;
				break;
			}
		case 52:
			{
				output2=12;
				break;
			}
		case 53:
			{
				output2=7;/////////////
				break;
			}
		case 54:
			{
				output2=6;
				break;
			}
		case 55:
			{
			    output2=12;
				break;
			}
		case 56:
			{
				output2=9;
				break;
			}
		case 57:
			{
				output2=0;
				break;
			}
		case 58:
			{
				output2=3;
				break;
			}
		case 59:
			{
				output2=5;
				break;
			}
		case 60:
			{
				output2=2;
				break;
			}
		case 61:
			{
				output2=14;
				break;
			}
		case 62:
			{
				output2=15;
				break;
			}
		case 63:
			{
				output2=9;
				break;
			}
}

			

////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////input3/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////


	switch (input6)
			{
		case 0 :
			{
			output3=10;
            break;
	        }
		case 1 :
			{
				output3=13;
				break;
			}
		case 2 :
			{
				output3=0;
				break;
			}
		case 3 :
			{
				output3=7;
				break;
			}
		case 4 :
					
			{
				output3=9;
				break;
			}
		case 5:
			{
				output3=0;
				break;
			}
		case 6:
			{
				output3=14;
				break;
			}
		case 7:
			{
				output3=9;
				break;
			}
		case 8:
			{
				output3=6;
				break;
			}
		case 9:
			{
				output3=3;
				break;
			}
		case 10:
			{
				output3=3;
				break;
			}
		case 11:
			{
				output3=4;
				break;
			}

		case 12:
			{
				output3=15;
				break;
			}
		case 13:
			{
				output3=6;
				break;
			}
		case 14:
			{
				output3=5;
				break;
			}
		case 15:
			{
				output3=10;
				break;
			}
		case 16:
			{
				output3=1;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output3=2;
				break;
			}
		case 18:
			{
				output3=13;
				break;
			}
		case 19:
			{
				output3=8;
				break;
			}
		case 20:
			{
				output3=12;
				break;

			}
		case 21:
			{
				output3=5;
				break;
			}
		case 22:
			{
				output3=7;
				break;
			}
		case 23:
			{
				output3=14;
				break;
			}
		case 24:
			{
				output3=11;
				break;
			}
		case 25:
			{
				output3=12;
				break;
			}
		case 26:
			{
				output3=4;
				break;

			}
		case 27:
			{
				output3=11;
				break;
			}
		case 28:
			{
				output3=2;
				break;
			}
		case 29:
			{
				output3=15;
				break;
			}
		case 30:
			{
				output3=8;
				break;
			}
		case 31:
			{
				output3=1;
				break;
			}
		case 32:
			{
				output3=13;
				break;
			}
		case 33:
			{
				output3=1;
				break;
			}
		case 34:
			{
				output3=6;
				break;
			}
		case 35:
			{
				output3=10;
				break;
			}
		case 36:
			{
				output3=4;
				break;
			}
		case 37:
			{
				output3=13;
				break;
			}
		case 38:
			{
				output3=9;
				break;
			}
		case 39:
			{
				output3=0;
				break;
			}
		case 40:
			{
				output3=8;
				break;
			}
		case 41:
			{
				output3=6;
				break;
			}
		case 42:
			{
				output3=15;
				break;
			}
		case 43:
			{
				output3=9;
				break;
			}

		case 44:
			{
				output3=3;
				break;
			}
		case 45:
			{
				output3=8;
				break;
			}
		case 46:
			{
				output3=0;
				break;
			}
		case 47:
			{
				output3=7;
				break;
			}
		case 48:
			{
				output3=11;
				break;
			}
		case 49:
			{
				output3=4;
				break;
			}
		case 50:
			{
				output3=1;
				break;
			}
		case 51:
			{
				output3=15;
				break;
			}
		case 52:
			{
				output3=2;
				break;
			}
		case 53:
			{
				output3=14;/////////////
				break;
			}
		case 54:
			{
				output3=12;
				break;
			}
		case 55:
			{
				output3=3;
				break;
			}
		case 56:
			{
				output3=5;
				break;
			}
		case 57:
			{
				output3=11;
				break;
			}
		case 58:
			{
				output3=10;
				break;
			}
		case 59:
			{
				output3=5;
				break;
			}
		case 60:
			{
				output3=14;
				break;
			}
		case 61:
			{
				output3=2;
				break;
			}
		case 62:
			{
				output3=7;
				break;
			}
		case 63:
			{
				output3=12;
				break;
			}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////input4///////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////
			switch (input5)
			{
		case 0 :
			{
			output4=7;
            break;
	        }
		case 1 :
			{
				output4=13;
				break;
			}
		case 2 :
			{
				output4=13;
				break;
			}
		case 3 :
			{
				output4=8;
				break;
			}
		case 4 :
					
			{
				output4=14;
				break;
			}
		case 5:
			{
				output4=11;
				break;
			}
		case 6:
			{
				output4=3;
				break;
			}
		case 7:
			{
				output4=5;
				break;
			}
		case 8:
			{
				output4=0;
				break;
			}
		case 9:
			{
				output4=6;
				break;
			}
		case 10:
			{
				output4=6;
				break;
			}
		case 11:
			{
				output4=15;
				break;
			}

		case 12:
			{
				output4=9;
				break;
			}
		case 13:
			{
				output4=0;
				break;
			}
		case 14:
			{
				output4=10;
				break;
			}
		case 15:
			{
				output4=3;
				break;
			}
		case 16:
			{
				output4=1;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output4=4;
				break;
			}
		case 18:
			{
				output4=2;
				break;
			}
		case 19:
			{
				output4=7;
				break;
			}
		case 20:
			{
				output4=8;
				break;

			}
		case 21:
			{
				output4=2;
				break;
			}
		case 22:
			{
				output4=5;
				break;
			}
		case 23:
			{
				output4=12;
				break;
			}
		case 24:
			{
				output4=11;
				break;
			}
		case 25:
			{
				output4=1;
				break;
			}
		case 26:
			{
				output4=12;
				break;

			}
		case 27:
			{
				output4=10;
				break;
			}
		case 28:
			{
				output4=4;
				break;
			}
		case 29:
			{
				output4=14;
				break;
			}
		case 30:
			{
				output4=15;
				break;
			}
		case 31:
			{
				output4=9;
				break;
			}
		case 32:
			{
				output4=10;
				break;
			}
		case 33:
			{
				output4=3;
				break;
			}
		case 34 :
			{
				output4=6;
				break;
			}
		case 35:
			{
				output4=15;
				break;
			}
		case 36:
			{
				output4=9;
				break;
			}
		case 37:
			{
				output4=0;
				break;
			}
		case 38:
			{
				output4=0;
				break;
			}
		case 39:
			{
				output4=6;
				break;
			}
		case 40:
			{
				output4=12;
				break;
			}
		case 41:
			{
				output4=10;
				break;
			}
		case 42:
			{
				output4=11;
				break;
			}
		case 43:
			{
				output4=1;
				break;
			}

		case 44:
			{
				output4=7;
				break;
			}
		case 45:
			{
				output4=13;
				break;
			}
		case 46:
			{
				output4=13;
				break;
			}
		case 47:
			{
				output4=8;
				break;
			}
		case 48:
			{
				output4=15;
				break;
			}
		case 49:
			{
				output4=9;
				break;
			}
		case 50:
			{
				output4=1;
				break;
			}
		case 51:
			{
				output4=4;
				break;
			}
		case 52:
			{
				output4=3;
				break;
			}
		case 53:
			{
				output4=5;/////////////
				break;
			}
		case 54:
			{
				output4=14;
				break;
			}
		case 55:
			{
				output4=11;
				break;
			}
		case 56:
			{
				output4=5;
				break;
			}
		case 57:
			{
				output4=12;
				break;
			}
		case 58:
			{
				output4=2;
				break;
			}
		case 59:
			{
				output4=7;
				break;
			}
		case 60:
			{
				output4=8;
				break;
			}
		case 61:
			{
				output4=2;
				break;
			}
		case 62:
			{
				output4=4;
				break;
			}
		case 63:
			{
				output4=14;
				break;
			}
}


	////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// INPUT 5///////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

switch (input4)
{

		case 0 : 
             {
			    output5=2 ;
                break;
	         }
		case 1 :
			{
				output5=14;
				break;
			}
		case 2 :
			{
				output5=12;
				break;
			}
		case 3 :
			{
				output5=11;
				break;
			}
		case 4 :
					
			{
				output5=4;
				break;
			}
		case 5:
			{
				output5=2;
				break;
			}
		case 6:
			{
				output5=1;
				break;
			}
		case 7:
			{
			    output5=12;
				break;
			}
		case 8:
			{
				output5=7;
				break;
			}
		case 9:
			{
				output5=4;
				break;
			}
		case 10:
			{
				output5=10;
				break;
			}
		case 11:
			{
				output5=7;
				break;
			}

		case 12:
			{
				output5=11;
				break;
			}
		case 13:
			{
				output5=13;
				break;
			}
		case 14:
			{
				output5=6;
				break;
			}
		case 15:
			{
				output5=1;
				break;
			}
		case 16:
			{
				output5=8;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output5=5;
				break;
			}
		case 18:
			{
				output5=5;
				break;
			}
		case 19:
			{
				output5=0;
				break;
			}
		case 20:
			{
				output5=3;
				break;

			}
		case 21:
			{
				output5=15;////////////////////
				break;
			}
		case 22:
			{
				output5=15;
				break;
			}
		case 23:
			{
				output5=10;
				break;
			}
		case 24:
			{
				output5=13;
				break;
			}
		case 25:
			{
				output5=3;
				break;
			}
		case 26:
			{
				output5=0;
				break;

			}
		case 27:
			{
				output5=9;
				break;
			}
		case 28:
			{
				output5=14;
				break;
			}
		case 29:
			{
				output5=8;
				break;
			}
		case 30:
			{
				output5=9;
				break;
			}
		case 31:
			{
				output5=6;
				break;
			}
		case 32:
			{
				output5=4;
				break;
			}
		case 33:
			{
				output5=11;
				break;
			}
		case 34 :
			{
				output5=2;
				break;
			}
		case 35:
			{
				output5=8;
				break;
			}
		case 36:
			{
				output5=1;
				break;
			}
		case 37:
			{
				output5=12;
				break;
			}
		case 38:
			{
				output5=11;
				break;
			}
		case 39:
			{
				output5=7;
				break;
			}
		case 40:
			{
				output5=10;
				break;
			}
		case 41:
			{
				output5=1;
				break;
			}
		case 42:
			{
				output5=13;
				break;
			}
		case 43:
			{
				output5=14;
				break;
			}

		case 44:
			{
				output5=7;
				break;
			}
		case 45:
			{
				output5=2;
				break;
			}
		case 46:
			{
				output5=8;
				break;
			}
		case 47:
			{
				output5=13;
				break;
			}
		case 48:
			{
				output5=15;
				break;
			}
		case 49:
			{
				output5=6;
				break;
			}
		case 50:
			{
				output5=9;
				break;
			}
		case 51:
			{
				output5=15;
				break;
			}
		case 52:
			{
				output5=12;
				break;
			}
		case 53:
			{
				output5=0;/////////////
				break;
			}
		case 54:
			{
				output5=5;
				break;
			}
		case 55:
			{
				output5=9;
				break;
			}
		case 56:
			{
				output5=6;
				break;
			}
		case 57:
			{
				output5=10;
				break;
			}
		case 58:
			{
				output5=3;
				break;
			}
		case 59:
			{
				output5=4;
				break;
			}
		case 60:
			{
				output5=0;
				break;
			}
		case 61:
			{
				output5=5;
				break;
			}
		case 62:
			{
				output5=14;
				break;
			}
		case 63:
			{
				output5=3;
				break;
			}

}

			////////////////////////////////////////////////////////////////////////////////////////////////
			///////////////////////////////////////////////////////////////////////////////////////////////
			///////////////////////////////////////////// INPUT 6///////////////////////////////////////////
			////////////////////////////////////////////////////////////////////////////////////////////////


switch (input3)
   {
		case 0 : 
             {
			    output6=12 ;
                break;
	         }
		case 1 :
			{
				output6=10;
				break;
			}
		case 2 :
			{
				output6=1;
				break;
			}
		case 3 :
			{
				output6=15;
				break;
			}
		case 4 :
					
			{
				output6=10;
				break;
			}
		case 5:
			{
				output6=4;//////////////////////
				break;
			}
		case 6:
			{
				output6=15;
				break;
			}
		case 7:
			{
			    output6=2;
				break;
			}
		case 8:
			{
				output6=9;
				break;
			}
		case 9:
			{
				output6=7;
				break;
			}
		case 10:
			{
				output6=2;
				break;
			}
		case 11:
			{
				output6=12;
				break;
			}

		case 12:
			{
				output6=6;
				break;
			}
		case 13:
			{
				output6=9;
				break;
			}
		case 14:
			{
				output6=8;
				break;
			}
		case 15:
			{
				output6=5;
				break;
			}
		case 16:
			{
				output6=0;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output6=6;
				break;
			}
		case 18:
			{
				output6=13;
				break;
			}
		case 19:
			{
				output6=1;
				break;
			}
		case 20:
			{
				output6=3;
				break;

			}
		case 21:
			{
				output6=13;////////////////////
				break;
			}
		case 22:
			{
				output6=4;
				break;
			}
		case 23:
			{
				output6=14;
				break;
			}
		case 24:
			{
				output6=14;
				break;
			}
		case 25:
			{
				output6=0;
				break;
			}
		case 26:
			{
				output6=7;
				break;

			}
		case 27:
			{
				output6=11;
				break;
			}
		case 28:
			{
				output6=5;
				break;
			}
		case 29:
			{
				output6=3;
				break;
			}
		case 30:
			{
				output6=11;
				break;
			}
		case 31:
			{
				output6=8;
				break;
			}
		case 32:
			{
				output6=9;
				break;
			}
		case 33:
			{
				output6=4;
				break;
			}
		case 34 :
			{
				output6=14;
				break;
			}
		case 35:
			{
				output6=3;
				break;
			}
		case 36:
			{
				output6=15;
				break;
			}
		case 37:
			{
				output6=2;
				break;
			}
		case 38:
			{
				output6=5;
				break;
			}
		case 39:
			{
				output6=12;
				break;
			}
		case 40:
			{
				output6=2;
				break;
			}
		case 41:
			{
				output6=9;
				break;
			}
		case 42:
			{
				output6=8;
				break;
			}
		case 43:
			{
				output6=5;
				break;
			}

		case 44:
			{
				output6=12;
				break;
			}
		case 45:
			{
				output6=15;
				break;
			}
		case 46:
			{
				output6=3;
				break;
			}
		case 47:
			{
				output6=10;
				break;
			}
		case 48:
			{
				output6=7;
				break;
			}
		case 49:
			{
				output6=11;
				break;
			}
		case 50:
			{
				output6=0;
				break;
			}
		case 51:
			{
				output6=14;
				break;
			}
		case 52:
			{
				output6=4;
				break;
			}
		case 53:
			{
				output6=1;/////////////
				break;
			}
		case 54:
			{
				output6=10;
				break;
			}
		case 55:
			{
				output6=7;
				break;
			}
		case 56:
			{
				output6=1;
				break;
			}
		case 57:
			{
				output6=6;
				break;
			}
		case 58:
			{
				output6=13;
				break;
			}
		case 59:
			{
				output6=0;
				break;
			}
		case 60:
			{
				output6=11;
				break;
			}
		case 61:
			{
				output6=8;
				break;
			}
		case 62:
			{
				output6=6;
				break;
			}
		case 63:
			{
				output6=13;
				break;
			}

			}

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////// INPUT 7 /////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////



switch (input2)
   {
		case 0 : 
             {
			    output7=4 ;
                break;
	         }
		case 1 :
			{
				output7=13;
				break;
			}
		case 2 :
			{
				output7=11;
				break;
			}
		case 3 :
			{
				output7=0;
				break;
			}
		case 4 :
					
			{
				output7=2;
				break;
			}
		case 5:
			{
				output7=11;//////////////////////
				break;
			}
		case 6:
			{
				output7=14;
				break;
			}
		case 7:
			{
			    output7=7;
				break;
			}
		case 8:
			{
				output7=15;
				break;
			}
		case 9:
			{
				output7=4;
				break;
			}
		case 10:
			{
				output7=0;
				break;
			}
		case 11:
			{
				output7=9;
				break;
			}

		case 12:
			{
				output7=8;
				break;
			}
		case 13:
			{
				output7=1;
				break;
			}
		case 14:
			{
				output7=13;
				break;
			}
		case 15:
			{
				output7=10;
				break;
			}
		case 16:
			{
				output7=3;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output7=14;
				break;
			}
		case 18:
			{
				output7=12;
				break;
			}
		case 19:
			{
				output7=3;
				break;
			}
		case 20:
			{
				output7=9;
				break;

			}
		case 21:
			{
				output7=5;////////////////////
				break;
			}
		case 22:
			{
				output7=7;
				break;
			}
		case 23:
			{
				output7=12;
				break;
			}
		case 24:
			{
				output7=5;
				break;
			}
		case 25:
			{
				output7=2;
				break;
			}
		case 26:
			{
				output7=10;
				break;

			}
		case 27:
			{
				output7=15;
				break;
			}
		case 28:
			{
				output7=6;
				break;
			}
		case 29:
			{
				output7=8;
				break;
			}
		case 30:
			{
				output7=1;
				break;
			}
		case 31:
			{
				output7=6;
				break;
			}
		case 32:
			{
				output7=1;
				break;
			}
		case 33:
			{
				output7=6;
				break;
			}
		case 34 :
			{
				output7=4;
				break;
			}
		case 35:
			{
				output7=11;
				break;
			}
		case 36:
			{
				output7=11;
				break;
			}
		case 37:
			{
				output7=13;
				break;
			}
		case 38:
			{
				output7=13;
				break;
			}
		case 39:
			{
				output7=8;
				break;
			}
		case 40:
			{
				output7=12;
				break;
			}
		case 41:
			{
				output7=1;
				break;
			}
		case 42:
			{
				output7=3;
				break;
			}
		case 43:
			{
				output7=4;
				break;
			}

		case 44:
			{
				output7=7;
				break;
			}
		case 45:
			{
				output7=10;
				break;
			}
		case 46:
			{
				output7=14;
				break;
			}
		case 47:
			{
				output7=7;
				break;
			}
		case 48:
			{
				output7=10;
				break;
			}
		case 49:
			{
				output7=9;
				break;
			}
		case 50:
			{
				output7=15;
				break;
			}
		case 51:
			{
				output7=5;
				break;
			}
		case 52:
			{
				output7=6;
				break;
			}
		case 53:
			{
				output7=0;/////////////
				break;
			}
		case 54:
			{
				output7=8;
				break;
			}
		case 55:
			{
				output7=15;
				break;
			}
		case 56:
			{
				output7=0;
				break;
			}
		case 57:
			{
				output7=14;
				break;
			}
		case 58:
			{
				output7=5;
				break;
			}
		case 59:
			{
				output7=2;
				break;
			}
		case 60:
			{
				output7=9;
				break;
			}
		case 61:
			{
				output7=3;
				break;
			}
		case 62:
			{
				output7=2;
				break;
			}
		case 63:
			{
				output7=12;
				break;
			}

			}

//////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// INPUT 8 ///////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

switch (input1)
   {
		case 0 : 
             {
			    output8=13 ;
                break;
	         }
		case 1 :
			{
				output8=1;
				break;
			}
		case 2 :
			{
				output8=2;
				break;
			}
		case 3 :
			{
				output8=15;
				break;
			}
		case 4 :
					
			{
				output8=8;
				break;
			}
		case 5:
			{
				output8=13;//////////////////////
				break;
			}
		case 6:
			{
				output8=4;
				break;
			}
		case 7:
			{
			    output8=8;
				break;
			}
		case 8:
			{
				output8=6;
				break;
			}
		case 9:
			{
				output8=10;
				break;
			}
		case 10:
			{
				output8=15;
				break;
			}
		case 11:
			{
				output8=3;
				break;
			}

		case 12:
			{
				output8=11;
				break;
			}
		case 13:
			{
				output8=7;
				break;
			}
		case 14:
			{
				output8=1;
				break;
			}
		case 15:
			{
				output8=4;
				break;
			}
		case 16:
			{
				output8=10;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output8=12;
				break;
			}
		case 18:
			{
				output8=9;
				break;
			}
		case 19:
			{
				output8=5;
				break;
			}
		case 20:
			{
				output8=3;
				break;

			}
		case 21:
			{
				output8=6;////////////////////
				break;
			}
		case 22:
			{
				output8=14;
				break;
			}
		case 23:
			{
				output8=11;
				break;
			}
		case 24:
			{
				output8=5;
				break;
			}
		case 25:
			{
				output8=0;
				break;
			}
		case 26:
			{
				output8=0;
				break;

			}
		case 27:
			{
				output8=14;
				break;
			}
		case 28:
			{
				output8=12;
				break;
			}
		case 29:
			{
				output8=9;
				break;
			}
		case 30:
			{
				output8=7;
				break;
			}
		case 31:
			{
				output8=2;
				break;
			}
		case 32:
			{
				output8=7;
				break;
			}
		case 33:
			{
				output8=2;
				break;
			}
		case 34 :
			{
				output8=11;
				break;
			}
		case 35:
			{
				output8=1;
				break;
			}
		case 36:
			{
				output8=4;
				break;
			}
		case 37:
			{
				output8=14;
				break;
			}
		case 38:
			{
				output8=1;
				break;
			}
		case 39:
			{
				output8=7;
				break;
			}
		case 40:
			{
				output8=9;
				break;
			}
		case 41:
			{
				output8=4;
				break;
			}
		case 42:
			{
				output8=12;
				break;
			}
		case 43:
			{
				output8=10;
				break;
			}

		case 44:
			{
				output8=14;
				break;
			}
		case 45:
			{
				output8=8;
				break;
			}
		case 46:
			{
				output8=2;
				break;
			}
		case 47:
			{
				output8=13;
				break;
			}
		case 48:
			{
				output8=0;
				break;
			}
		case 49:
			{
				output8=15;
				break;
			}
		case 50:
			{
				output8=6;
				break;
			}
		case 51:
			{
				output8=12;
				break;
			}
		case 52:
			{
				output8=10;
				break;
			}
		case 53:
			{
				output8=9;/////////////
				break;
			}
		case 54:
			{
				output8=13;
				break;
			}
		case 55:
			{
				output8=0;
				break;
			}
		case 56:
			{
				output8=15;
				break;
			}
		case 57:
			{
				output8=3;
				break;
			}
		case 58:
			{
				output8=3;
				break;
			}
		case 59:
			{
				output8=5;
				break;
			}
		case 60:
			{
				output8=5;
				break;
			}
		case 61:
			{
				output8=6;
				break;
			}
		case 62:
			{
				output8=8;
				break;
			}
		case 63:
			{
				output8=11;
				break;
			}

			}

//////////////////////////////////// Output evaluation //////////////////////////////////////////

			output = output1<<28 | output2<<24 | output3<<20 | output4<<16 | output5<<12 | output6<<8 | output7<<4 | output8 ;
			/*
					for(int s=0;s<8;s++)  
					{
						frame = 0;
						frame  = input & LONGBIT_64_6(s*6); // Fetching the frame 
						frame = frame>>(s*6);
		
						if(frame%2 == 0) // if the frame contain even number
						{
							if(frame <32)
							{
								row = 0;
								column = frame>>1;
							}
							else if(frame >= 32)
							{
								row = 2;
								column = (frame-32)>>1;
							}
						}
						else                          // if the frame contain odd number 
						{
							if(frame <33)
							{
								row = 1;
								column = frame>>1;
							}
							else if(frame >= 33)
							{
								row = 3;
								column = (frame-32)>>1;
							}
						}
					/////////////// assgning values into output ///////////////////////
					output |= Sbox[7-s][row][column]<<(4*s);
		
					}*/
					sOutput=output;
				////////////////////////////////////////////////////
				//last permutation in the F-function after s-box

				xorInput=0;
				//////////////////////////////////////////////////////////////////////
				/////////////////////////////////////////////////////////////////////
				xorInput|= ((sOutput&0x00010000))<<15;//bit no (16)
				xorInput|= ((sOutput&0x02020120))<<5;//bit no (25,17,8,5)
				xorInput|= ((sOutput&0x00001800))<<17;//bit no (12,11)
				xorInput|= ((sOutput&0x00000008))<<24;//bit no (3)
				xorInput|= ((sOutput&0x00100000))<<6;//bit no (20)
				xorInput|= ((sOutput&0x00000010))<<21;//bit no (4)
				xorInput|= ((sOutput&0x00008000))<<9;//bit no (15)
				xorInput|= ((sOutput&0x00000200))<<12;//bit no (9)
				xorInput|= ((sOutput&0x00000040))<<14;//bit no (6)
				xorInput|= ((sOutput&0x00004000))<<4;//bit no (14)
				xorInput|= ((sOutput&0x00000002))<<16;//bit no (1)
				xorInput|= ((sOutput&0x00000001))<<11;//bit no (0)
				xorInput|= ((sOutput&0x00000004))<<3;//bit no (2)
				xorInput|= ((sOutput&0x88000000))>>8;//bit no (31,27)
				xorInput|= ((sOutput&0x00442000))>>6;//bit no (22,18,13)
				xorInput|= ((sOutput&0x40800000))>>15;//bit no (30,23)
				xorInput|= ((sOutput&0x01000000))>>10;//bit no (24)
				xorInput|= ((sOutput&0x20000000))>>20;//bit no (29)
				xorInput|= ((sOutput&0x00080000))>>13;//bit no (19)
				xorInput|= ((sOutput&0x04000000))>>22;//bit no (26)
				xorInput|= ((sOutput&0x00000480))>>7;//bit no (10,7)
				xorInput|= ((sOutput&0x00200000))>>19;//bit no (21)
				xorInput|= ((sOutput&0x10000000))>>27;//bit no (28)
			
				//////////////////////////////////////////////////////////
				////xor to get new left and right data 
			
			
				temp=xorInput^leftData;
				leftData=rightData;
				rightData=temp;



					
			}
			///////////////////////////////////////////////////////////////////// swap///////////////////////////////////////////////////////////
		
				long long dataToInversePermutation=0;
				temp=0;
				temp=(long long)leftData;
				leftData=rightData;
				rightData=temp;

				dataToInversePermutation|=((((long long)leftData)<<32)|(((long long)rightData) &0x00000000FFFFFFFF));
		
			///////////////////////////////////////////////////////////////////// Inverse Intial permutation/////////////////////////////////////
		
			int iIPCounter;
			long long dataOutput;
			dataOutput=0;
			dataOutput|= ((dataToInversePermutation&0x0000040000200000))<<0;
			dataOutput|= ((dataToInversePermutation&0x0002000010000040))<<3;
			dataOutput|= ((dataToInversePermutation&0x0100000400002000))<<6;
			dataOutput|= ((dataToInversePermutation&0x0000020000100000))<<9;
			dataOutput|= ((dataToInversePermutation&0x0001000008000020))<<12;
			dataOutput|= ((dataToInversePermutation&0x0000000200001000))<<15;
			dataOutput|= ((dataToInversePermutation&0x0000010000080000))<<18;
			dataOutput|= ((dataToInversePermutation&0x0000000004000010))<<21;
			dataOutput|= ((dataToInversePermutation&0x0000000100000800))<<24;
			dataOutput|= ((dataToInversePermutation&0x0000000000040000))<<27;
			dataOutput|= ((dataToInversePermutation&0x0000000002000008))<<30;
			dataOutput|= ((dataToInversePermutation&0x0000000000000400))<<33;
			dataOutput|= ((dataToInversePermutation&0x0000000000020000))<<36;
			dataOutput|= ((dataToInversePermutation&0x0000000001000004))<<39;
			dataOutput|= ((dataToInversePermutation&0x0000000000000200))<<42;
			dataOutput|= ((dataToInversePermutation&0x0000000000010000))<<45;
			dataOutput|= ((dataToInversePermutation&0x0000000000000002))<<48;
			dataOutput|= ((dataToInversePermutation&0x0000000000000100))<<51;
			dataOutput|= ((dataToInversePermutation&0x0000000000000001))<<57;
			///////////////////////////////////////////////////////////////////////////
			dataOutput|= ((dataToInversePermutation&0x0200000800004000))>>3;
			dataOutput|= ((dataToInversePermutation&0x0004000020000080))>>6;
			dataOutput|= ((dataToInversePermutation&0x0000080000400000))>>9;
			dataOutput|= ((dataToInversePermutation&0x0400001000008000))>>12;
			dataOutput|= ((dataToInversePermutation&0x0008000040000000))>>15;
			dataOutput|= ((dataToInversePermutation&0x0000100000800000))>>18;
			dataOutput|= ((dataToInversePermutation&0x0800002000000000))>>21;
			dataOutput|= ((dataToInversePermutation&0x0010000080000000))>>24;
			dataOutput|= ((dataToInversePermutation&0x0000200000000000))>>27;
			dataOutput|= ((dataToInversePermutation&0x1000004000000000))>>30;
			dataOutput|= ((dataToInversePermutation&0x0020000000000000))>>33;
			dataOutput|= ((dataToInversePermutation&0x0000400000000000))>>36;
			dataOutput|= ((dataToInversePermutation&0x2000008000000000))>>39;
			dataOutput|= ((dataToInversePermutation&0x0040000000000000))>>42;
			dataOutput|= ((dataToInversePermutation&0x0000800000000000))>>45;
			dataOutput|= ((dataToInversePermutation&0x4000000000000000))>>48;
			dataOutput|= ((dataToInversePermutation&0x0080000000000000))>>51;
			dataOutput|= ((dataToInversePermutation&0x8000000000000000))>>57;
			/////////////////////////////////////////////////////////////////
			/// write data to cipher text
			Write64Bit(pCipherTextFile,&dataOutput);

		}//Finished reading+

	printf("\n >>Encryption completed successfully !");
	}
	/////////////////////////////////////////////////////////////////////////Decryption///////////////////////////////////////////////////
	else if(stricmp(argv[1], "decrypt")==0)
	{
		
		
		pCipherTextFile = fopen((const char*)argv[2], "rb");
		plainTextFile = fopen((const char*)argv[4], "wb");
		fseek(pCipherTextFile, 0, SEEK_END);//pointer to the file  that required to know its lenght
		fileLength = ftell(pCipherTextFile);//tell the size of the file
		completeBlockCount = fileLength / 8 ;
		fseek(pCipherTextFile, 0, SEEK_SET);//return the pionter to the begining of the file
				
		
		if(plainTextFile==0)
		{
			printf("Error opening plaintext file.");
			return 0;
		}
		if(pCipherTextFile==0) 
		{
			printf("Error opening cipher file.");
			return 0;
		}

		printf("\n >>Decryption in progress");
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		/// variable declaration 
		
		bool readingOk = true;
		long long data64Bit =0;
		long long dataAfterIP,dataBeforeIP = 0;
		long long rDataAfterExpansion;
		long rightData , leftData ;
		int expCounter ;
		long sOutput ;			
		long  xorInput;
		int iPCounter;
		int roundCounter;
		int perm32Counter ;
		long long temp; //////change the name to exchange right and left data

		/////////////////////////////////////////////////////////////////////////////////
		/// Decryption code
		int count1=1;
		//////////////////////////////////////////////////
		//Will keep reading data until EOF is returned (b is false)
		while(Load64Bit1(pCipherTextFile ,&dataBeforeIP))
		{
			
			////////////////////////////////////////////////////////////////////////
			//initial permutation
		
			dataAfterIP=0;
		
			dataAfterIP|= ((dataBeforeIP&0x0000040000200000))<<0;
			dataAfterIP|= ((dataBeforeIP&0x0040000100000800))<<3;
			dataAfterIP|= ((dataBeforeIP&0x0000100000800002))<<6;
			dataAfterIP|= ((dataBeforeIP&0x0000000400002000))<<9;
			dataAfterIP|= ((dataBeforeIP&0x0000400001000008))<<12;
			dataAfterIP|= ((dataBeforeIP&0x0000001000008000))<<15;
			dataAfterIP|= ((dataBeforeIP&0x0000000004000020))<<18;
			dataAfterIP|= ((dataBeforeIP&0x0000004000010000))<<21;
			dataAfterIP|= ((dataBeforeIP&0x0000000010000080))<<24;
			dataAfterIP|= ((dataBeforeIP&0x0000000000040000))<<27;
			dataAfterIP|= ((dataBeforeIP&0x0000000040000100))<<30;
			dataAfterIP|= ((dataBeforeIP&0x0000000000100000))<<33;
			dataAfterIP|= ((dataBeforeIP&0x0000000000000400))<<36;
			dataAfterIP|= ((dataBeforeIP&0x0000000000400001))<<39;
			dataAfterIP|= ((dataBeforeIP&0x0000000000001000))<<42;
			dataAfterIP|= ((dataBeforeIP&0x0000000000000004))<<45;
			dataAfterIP|= ((dataBeforeIP&0x0000000000004000))<<48;
			dataAfterIP|= ((dataBeforeIP&0x0000000000000010))<<51;
			dataAfterIP|= ((dataBeforeIP&0x0000000000000040))<<57;
			///////////////////////////////////////////////////////////////////////////
			dataAfterIP|= ((dataBeforeIP&0x0010000080000200))>>3;
			dataAfterIP|= ((dataBeforeIP&0x4000010000080000))>>6;
			dataAfterIP|= ((dataBeforeIP&0x0004000020000000))>>9;
			dataAfterIP|= ((dataBeforeIP&0x1000008000020000))>>12;
			dataAfterIP|= ((dataBeforeIP&0x0001000008000000))>>15;
			dataAfterIP|= ((dataBeforeIP&0x0400002000000000))>>18;
			dataAfterIP|= ((dataBeforeIP&0x0000800002000000))>>21;
			dataAfterIP|= ((dataBeforeIP&0x0100000800000000))>>24;
			dataAfterIP|= ((dataBeforeIP&0x0000200000000000))>>27;
			dataAfterIP|= ((dataBeforeIP&0x0080000200000000))>>30;
			dataAfterIP|= ((dataBeforeIP&0x0000080000000000))>>33;
			dataAfterIP|= ((dataBeforeIP&0x0020000000000000))>>36;
			dataAfterIP|= ((dataBeforeIP&0x8000020000000000))>>39;
			dataAfterIP|= ((dataBeforeIP&0x0008000000000000))>>42;
			dataAfterIP|= ((dataBeforeIP&0x2000000000000000))>>45;
			dataAfterIP|= ((dataBeforeIP&0x0002000000000000))>>48;
			dataAfterIP|= ((dataBeforeIP&0x0800000000000000))>>51;
			dataAfterIP|= ((dataBeforeIP&0x0200000000000000))>>57;


			///////////////////////////////////////////////////////////////////////////////////////////////////////
			//dividing data into right and left for the rounds

				rightData = dataAfterIP;
				leftData = dataAfterIP>>32;
			
			


			for( roundCounter =0 ;roundCounter< 16;roundCounter++)
				{
				////////////////////////////////////////////////////
				// expansion permutation

			
				rDataAfterExpansion = 0 ;


					rDataAfterExpansion|= ((long long)(rightData&0x00000001))<<47; // 0
					rDataAfterExpansion|= ((long long)(rightData&0xf8000000))<<15;   //1-5
					rDataAfterExpansion|= ((long long)(rightData&0x1f800000))<<13;   //4-9
					rDataAfterExpansion|= ((long long)(rightData&0x01f80000))<<11;   //8-13
					rDataAfterExpansion|= ((long long)(rightData&0x001f8000))<<9;   //12-17
					rDataAfterExpansion|= ((long long)(rightData&0x0001f800))<<7;   //16-21
					rDataAfterExpansion|= ((long long)(rightData&0x00001f80))<<5;   //20-25
					rDataAfterExpansion|= ((long long)(rightData&0x000001f8))<<3;  //24-29
					rDataAfterExpansion|= ((long long)(rightData&0x0000001f))<<01;  //28-32
					rDataAfterExpansion|= ((long long)(rightData&0x80000000))>>31;  //1 

				/////////////////////////////////////////////////////
				//xor  with the key
				rDataAfterExpansion^=key_48[15-roundCounter];

				////////////////////////////////////////////////////
				// S-box
					//sOutput = sBox(rDataAfterExpansion);
					long long input= 0;
					long long output = 0;
					long long  frame=0;
					short row=0;
					short column=0;
					int bit_num;
					input=rDataAfterExpansion;
					long long  input1=0;
					long long  input2=0;
					long long  input3=0;
					long long  input4=0;
					long long  input5=0;
					long long  input6=0;
					long long  input7=0;
					long long  input8=0;
	
					long long  output1=0;
					long long  output2=0;
					long long  output3=0;
					long long  output4=0;
					long long  output5=0;
					long long  output6=0;
					long long  output7=0;
					long long  output8=0;
				
					/////////////////////////////////////////////////////////////////////////
///////////////////// Fetching the 8 frames ////////////////////////////
	input1 = (input & LONGBIT_64_6(0));//& 0x000000000000003F; // least

	input2 = ((input & LONGBIT_64_6(6))>>6) ;//& 0x000000000000003F;

	input3 = ((input & LONGBIT_64_6(12))>>12) ;//& 0x000000000000003F;

	input4 = ((input & LONGBIT_64_6(18))>>18);// & 0x000000000000003F;

	input5 = ((input & LONGBIT_64_6(24))>>24) ;//& 0x000000000000003F;

	input6 = ((input & LONGBIT_64_6(30))>>30) ;//& 0x000000000000003F;

	input7 = ((input & LONGBIT_64_6(36))>>36) ;//& 0x000000000000003F;

	input8 = ((input & LONGBIT_64_6(42))>>42);// & 0x000000000000003F; // most
/////////////////////////////////////////// LUTs //////////////////////////////////
	switch (input8)
	{
		case 0 : {
					output1=14 ;
            		break;
				 }
		case 1 :
			{
				output1=0;
				break;
			}
		case 2 :
			{
				output1=4;
				break;
			}
		case 3 :
			{
				output1=15;
				break;
			}
		case 4 :
					
			{
				output1=13;
				break;
			}
		case 5:
			{
				output1=7;
				break;
			}
		case 6:
			{
				output1=1;
				break;
			}
		case 7:
			{
			    output1=4;
				break;
			}
		case 8:
			{
				output1=2;
				break;
			}
		case 9:
			{
				output1=14;
				break;
			}
		case 10:
			{
				output1=15;
				break;
			}
		case 11:
			{
				output1=2;
				break;
			}

		case 12:
			{
				output1=11;
				break;
			}
		case 13:
			{
				output1=13;
				break;
			}
		case 14:
			{
				output1=8;
				break;
			}
		case 15:
			{
				output1=1;
				break;
			}
		case 16:
			{
				output1=3;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output1=10;
				break;
			}
		case 18:
			{
				output1=10;
				break;
			}
		case 19:
			{
				output1=6;
				break;
			}
		case 20:
			{
				output1=6;
				break;

			}
		case 21:
			{
				output1=12;
				break;
			}
		case 22:
			{
				output1=12;
				break;
			}
		case 23:
			{
				output1=11;
				break;
			}
		case 24:
			{
				output1=5;
				break;
			}
		case 25:
			{
				output1=9;
				break;
			}
		case 26:
			{
				output1=9;
				break;

			}
		case 27:
			{
				output1=5;
				break;
			}
		case 28:
			{
				output1=0;
				break;
			}
		case 29:
			{
				output1=3;
				break;
			}
		case 30:
			{
				output1=7;
				break;
			}
		case 31:
			{
				output1=8;
				break;
			}
		case 32:
			{
				output1=4;
				break;
			}
		case 33:
			{
				output1=15;
				break;
			}
		case 34 :
			{
				output1=1;
				break;
			}
		case 35:
			{
				output1=12;
				break;
			}
		case 36:
			{
				output1=14;
				break;
			}
		case 37:
			{
				output1=8;
				break;
			}
		case 38:
			{
				output1=8;
				break;
			}
		case 39:
			{
				output1=2;
				break;
			}
		case 40:
			{
				output1=13;
				break;
			}
		case 41:
			{
				output1=4;
				break;
			}
		case 42:
			{
				output1=6;
				break;
			}
		case 43:
			{
				output1=9;
				break;
			}

		case 44:
			{
				output1=2;
				break;
			}
		case 45:
			{
				output1=1;
				break;
			}
		case 46:
			{
				output1=11;
				break;
			}
		case 47:
			{
				output1=7;
				break;
			}
		case 48:
			{
				output1=15;
				break;
			}
		case 49:
			{
				output1=5;
				break;
			}
		case 50:
			{
				output1=12;
				break;
			}
		case 51:
			{
				output1=11;
				break;
			}
		case 52:
			{
				output1=9;
				break;
			}
		case 53:
			{
				output1=3;///////////// wrong 8
				break;
			}
		case 54:
			{
				output1=7;
				break;
			}
		case 55:
			{
				output1=14;
				break;
			}
		case 56:
			{
				output1=3;
				break;
			}
		case 57:
			{
				output1=10;
				break;
			}
		case 58:
			{
				output1=10;
				break;
			}
		case 59:
			{
				output1=0;
				break;
			}
		case 60:
			{
				output1=5;
				break;
			}
		case 61:
			{
				output1=6;
				break;
			}
		case 62:
			{
				output1=0;
				break;
			}
		case 63:
			{
				output1=13;
				break;
			}

			} 


			///////////////////////////////////////////////////////////////////////////////////////
			//////////////////////////////input2///////////////////////////////////////////////////
			///////////////////////////////////////////////////////////////////////////////////////
			switch (input7)
			{
		case 0 : {
			output2=15;
            break;
				}
		case 1 :
			{
				output2=3;
				break;
			}
		case 2:
			{
				output2=1;
				break;
			}
		case 3 :
			{
				output2=13;
				break;
			}
		case 4 :
					
			{
				output2=8;
				break;
			}
		case 5:
			{
				output2=4;
				break;
			}
		case 6:
			{
				output2=14;
				break;
			}
		case 7:
			{
				output2=7;
				break;
			}
		case 8:
			{
				output2=6;
				break;
			}
		case 9:
			{
				output2=15;
				break;
			}
		case 10:
			{
				output2=11;
				break;
			}
		case 11:
			{
				output2=2;
				break;
			}

		case 12:
			{
				output2=3;
				break;
			}
		case 13:
			{
				output2=8;
				break;
			}
		case 14:
			{
				output2=4;
				break;
			}
		case 15:
			{
				output2=14;
				break;
			}
		case 16:
			{
				output2=9;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output2=12;
				break;
			}
		case 18:
			{
				output2=7;
				break;
			}
		case 19:
			{
				output2=0;
				break;
			}
		case 20:
			{
				output2=2;
				break;

			}
		case 21:
			{
				output2=1;
				break;
			}
		case 22:
			{
				output2=13;
				break;
			}
		case 23:
			{
				output2=10;
				break;
			}
		case 24:
			{
				output2=12;
				break;
			}
		case 25:
			{
				output2=6;
				break;
			}
		case 26:
			{
				output2=0;
				break;

			}
		case 27:
			{
				output2=9;
				break;
			}
		case 28:
			{
				output2=5;
				break;
			}
		case 29:
			{
				output2=11;
				break;
			}
		case 30:
			{
				output2=10;
				break;
			}
		case 31:
			{
				output2=5;
				break;
			}
		case 32:
			{
				output2=0;
				break;
			}
		case 33:
			{
				output2=13;
				break;
			}
		case 34 :
			{
				output2=14;
				break;
			}
		case 35:
			{
				output2=8;
				break;
			}
		case 36:
			{
				output2=7;
				break;
			}
		case 37:
			{
				output2=10;
				break;
			}
		case 38:
			{
				output2=11;
				break;
			}
		case 39:
			{
				output2=1;
				break;
			}
		case 40:
			{
				output2=10;
				break;
			}
		case 41:
			{
				output2=3;
				break;
			}
		case 42:
			{
				output2=4;
				break;
			}
		case 43:
			{
				output2=15;
				break;
			}

		case 44:
			{
				output2=13;
				break;
			}
		case 45:
			{
				output2=4;
				break;
			}
		case 46:
			{
				output2=1;
				break;
			}
		case 47:
			{
				output2=2;
				break;
			}
		case 48:
			{
				output2=5;
				break;
			}
		case 49:
			{
				output2=11;
				break;
			}
		case 50:
			{
				output2=8;
				break;
			}
		case 51:
			{
				output2=6;
				break;
			}
		case 52:
			{
				output2=12;
				break;
			}
		case 53:
			{
				output2=7;/////////////
				break;
			}
		case 54:
			{
				output2=6;
				break;
			}
		case 55:
			{
			    output2=12;
				break;
			}
		case 56:
			{
				output2=9;
				break;
			}
		case 57:
			{
				output2=0;
				break;
			}
		case 58:
			{
				output2=3;
				break;
			}
		case 59:
			{
				output2=5;
				break;
			}
		case 60:
			{
				output2=2;
				break;
			}
		case 61:
			{
				output2=14;
				break;
			}
		case 62:
			{
				output2=15;
				break;
			}
		case 63:
			{
				output2=9;
				break;
			}
}

			

////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////input3/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////


	switch (input6)
			{
		case 0 :
			{
			output3=10;
            break;
	        }
		case 1 :
			{
				output3=13;
				break;
			}
		case 2 :
			{
				output3=0;
				break;
			}
		case 3 :
			{
				output3=7;
				break;
			}
		case 4 :
					
			{
				output3=9;
				break;
			}
		case 5:
			{
				output3=0;
				break;
			}
		case 6:
			{
				output3=14;
				break;
			}
		case 7:
			{
				output3=9;
				break;
			}
		case 8:
			{
				output3=6;
				break;
			}
		case 9:
			{
				output3=3;
				break;
			}
		case 10:
			{
				output3=3;
				break;
			}
		case 11:
			{
				output3=4;
				break;
			}

		case 12:
			{
				output3=15;
				break;
			}
		case 13:
			{
				output3=6;
				break;
			}
		case 14:
			{
				output3=5;
				break;
			}
		case 15:
			{
				output3=10;
				break;
			}
		case 16:
			{
				output3=1;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output3=2;
				break;
			}
		case 18:
			{
				output3=13;
				break;
			}
		case 19:
			{
				output3=8;
				break;
			}
		case 20:
			{
				output3=12;
				break;

			}
		case 21:
			{
				output3=5;
				break;
			}
		case 22:
			{
				output3=7;
				break;
			}
		case 23:
			{
				output3=14;
				break;
			}
		case 24:
			{
				output3=11;
				break;
			}
		case 25:
			{
				output3=12;
				break;
			}
		case 26:
			{
				output3=4;
				break;

			}
		case 27:
			{
				output3=11;
				break;
			}
		case 28:
			{
				output3=2;
				break;
			}
		case 29:
			{
				output3=15;
				break;
			}
		case 30:
			{
				output3=8;
				break;
			}
		case 31:
			{
				output3=1;
				break;
			}
		case 32:
			{
				output3=13;
				break;
			}
		case 33:
			{
				output3=1;
				break;
			}
		case 34:
			{
				output3=6;
				break;
			}
		case 35:
			{
				output3=10;
				break;
			}
		case 36:
			{
				output3=4;
				break;
			}
		case 37:
			{
				output3=13;
				break;
			}
		case 38:
			{
				output3=9;
				break;
			}
		case 39:
			{
				output3=0;
				break;
			}
		case 40:
			{
				output3=8;
				break;
			}
		case 41:
			{
				output3=6;
				break;
			}
		case 42:
			{
				output3=15;
				break;
			}
		case 43:
			{
				output3=9;
				break;
			}

		case 44:
			{
				output3=3;
				break;
			}
		case 45:
			{
				output3=8;
				break;
			}
		case 46:
			{
				output3=0;
				break;
			}
		case 47:
			{
				output3=7;
				break;
			}
		case 48:
			{
				output3=11;
				break;
			}
		case 49:
			{
				output3=4;
				break;
			}
		case 50:
			{
				output3=1;
				break;
			}
		case 51:
			{
				output3=15;
				break;
			}
		case 52:
			{
				output3=2;
				break;
			}
		case 53:
			{
				output3=14;/////////////
				break;
			}
		case 54:
			{
				output3=12;
				break;
			}
		case 55:
			{
				output3=3;
				break;
			}
		case 56:
			{
				output3=5;
				break;
			}
		case 57:
			{
				output3=11;
				break;
			}
		case 58:
			{
				output3=10;
				break;
			}
		case 59:
			{
				output3=5;
				break;
			}
		case 60:
			{
				output3=14;
				break;
			}
		case 61:
			{
				output3=2;
				break;
			}
		case 62:
			{
				output3=7;
				break;
			}
		case 63:
			{
				output3=12;
				break;
			}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////input4///////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////
			switch (input5)
			{
		case 0 :
			{
			output4=7;
            break;
	        }
		case 1 :
			{
				output4=13;
				break;
			}
		case 2 :
			{
				output4=13;
				break;
			}
		case 3 :
			{
				output4=8;
				break;
			}
		case 4 :
					
			{
				output4=14;
				break;
			}
		case 5:
			{
				output4=11;
				break;
			}
		case 6:
			{
				output4=3;
				break;
			}
		case 7:
			{
				output4=5;
				break;
			}
		case 8:
			{
				output4=0;
				break;
			}
		case 9:
			{
				output4=6;
				break;
			}
		case 10:
			{
				output4=6;
				break;
			}
		case 11:
			{
				output4=15;
				break;
			}

		case 12:
			{
				output4=9;
				break;
			}
		case 13:
			{
				output4=0;
				break;
			}
		case 14:
			{
				output4=10;
				break;
			}
		case 15:
			{
				output4=3;
				break;
			}
		case 16:
			{
				output4=1;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output4=4;
				break;
			}
		case 18:
			{
				output4=2;
				break;
			}
		case 19:
			{
				output4=7;
				break;
			}
		case 20:
			{
				output4=8;
				break;

			}
		case 21:
			{
				output4=2;
				break;
			}
		case 22:
			{
				output4=5;
				break;
			}
		case 23:
			{
				output4=12;
				break;
			}
		case 24:
			{
				output4=11;
				break;
			}
		case 25:
			{
				output4=1;
				break;
			}
		case 26:
			{
				output4=12;
				break;

			}
		case 27:
			{
				output4=10;
				break;
			}
		case 28:
			{
				output4=4;
				break;
			}
		case 29:
			{
				output4=14;
				break;
			}
		case 30:
			{
				output4=15;
				break;
			}
		case 31:
			{
				output4=9;
				break;
			}
		case 32:
			{
				output4=10;
				break;
			}
		case 33:
			{
				output4=3;
				break;
			}
		case 34 :
			{
				output4=6;
				break;
			}
		case 35:
			{
				output4=15;
				break;
			}
		case 36:
			{
				output4=9;
				break;
			}
		case 37:
			{
				output4=0;
				break;
			}
		case 38:
			{
				output4=0;
				break;
			}
		case 39:
			{
				output4=6;
				break;
			}
		case 40:
			{
				output4=12;
				break;
			}
		case 41:
			{
				output4=10;
				break;
			}
		case 42:
			{
				output4=11;
				break;
			}
		case 43:
			{
				output4=1;
				break;
			}

		case 44:
			{
				output4=7;
				break;
			}
		case 45:
			{
				output4=13;
				break;
			}
		case 46:
			{
				output4=13;
				break;
			}
		case 47:
			{
				output4=8;
				break;
			}
		case 48:
			{
				output4=15;
				break;
			}
		case 49:
			{
				output4=9;
				break;
			}
		case 50:
			{
				output4=1;
				break;
			}
		case 51:
			{
				output4=4;
				break;
			}
		case 52:
			{
				output4=3;
				break;
			}
		case 53:
			{
				output4=5;/////////////
				break;
			}
		case 54:
			{
				output4=14;
				break;
			}
		case 55:
			{
				output4=11;
				break;
			}
		case 56:
			{
				output4=5;
				break;
			}
		case 57:
			{
				output4=12;
				break;
			}
		case 58:
			{
				output4=2;
				break;
			}
		case 59:
			{
				output4=7;
				break;
			}
		case 60:
			{
				output4=8;
				break;
			}
		case 61:
			{
				output4=2;
				break;
			}
		case 62:
			{
				output4=4;
				break;
			}
		case 63:
			{
				output4=14;
				break;
			}
}


	////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// INPUT 5///////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

switch (input4)
{

		case 0 : 
             {
			    output5=2 ;
                break;
	         }
		case 1 :
			{
				output5=14;
				break;
			}
		case 2 :
			{
				output5=12;
				break;
			}
		case 3 :
			{
				output5=11;
				break;
			}
		case 4 :
					
			{
				output5=4;
				break;
			}
		case 5:
			{
				output5=2;
				break;
			}
		case 6:
			{
				output5=1;
				break;
			}
		case 7:
			{
			    output5=12;
				break;
			}
		case 8:
			{
				output5=7;
				break;
			}
		case 9:
			{
				output5=4;
				break;
			}
		case 10:
			{
				output5=10;
				break;
			}
		case 11:
			{
				output5=7;
				break;
			}

		case 12:
			{
				output5=11;
				break;
			}
		case 13:
			{
				output5=13;
				break;
			}
		case 14:
			{
				output5=6;
				break;
			}
		case 15:
			{
				output5=1;
				break;
			}
		case 16:
			{
				output5=8;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output5=5;
				break;
			}
		case 18:
			{
				output5=5;
				break;
			}
		case 19:
			{
				output5=0;
				break;
			}
		case 20:
			{
				output5=3;
				break;

			}
		case 21:
			{
				output5=15;////////////////////
				break;
			}
		case 22:
			{
				output5=15;
				break;
			}
		case 23:
			{
				output5=10;
				break;
			}
		case 24:
			{
				output5=13;
				break;
			}
		case 25:
			{
				output5=3;
				break;
			}
		case 26:
			{
				output5=0;
				break;

			}
		case 27:
			{
				output5=9;
				break;
			}
		case 28:
			{
				output5=14;
				break;
			}
		case 29:
			{
				output5=8;
				break;
			}
		case 30:
			{
				output5=9;
				break;
			}
		case 31:
			{
				output5=6;
				break;
			}
		case 32:
			{
				output5=4;
				break;
			}
		case 33:
			{
				output5=11;
				break;
			}
		case 34 :
			{
				output5=2;
				break;
			}
		case 35:
			{
				output5=8;
				break;
			}
		case 36:
			{
				output5=1;
				break;
			}
		case 37:
			{
				output5=12;
				break;
			}
		case 38:
			{
				output5=11;
				break;
			}
		case 39:
			{
				output5=7;
				break;
			}
		case 40:
			{
				output5=10;
				break;
			}
		case 41:
			{
				output5=1;
				break;
			}
		case 42:
			{
				output5=13;
				break;
			}
		case 43:
			{
				output5=14;
				break;
			}

		case 44:
			{
				output5=7;
				break;
			}
		case 45:
			{
				output5=2;
				break;
			}
		case 46:
			{
				output5=8;
				break;
			}
		case 47:
			{
				output5=13;
				break;
			}
		case 48:
			{
				output5=15;
				break;
			}
		case 49:
			{
				output5=6;
				break;
			}
		case 50:
			{
				output5=9;
				break;
			}
		case 51:
			{
				output5=15;
				break;
			}
		case 52:
			{
				output5=12;
				break;
			}
		case 53:
			{
				output5=0;/////////////
				break;
			}
		case 54:
			{
				output5=5;
				break;
			}
		case 55:
			{
				output5=9;
				break;
			}
		case 56:
			{
				output5=6;
				break;
			}
		case 57:
			{
				output5=10;
				break;
			}
		case 58:
			{
				output5=3;
				break;
			}
		case 59:
			{
				output5=4;
				break;
			}
		case 60:
			{
				output5=0;
				break;
			}
		case 61:
			{
				output5=5;
				break;
			}
		case 62:
			{
				output5=14;
				break;
			}
		case 63:
			{
				output5=3;
				break;
			}

}

			////////////////////////////////////////////////////////////////////////////////////////////////
			///////////////////////////////////////////////////////////////////////////////////////////////
			///////////////////////////////////////////// INPUT 6///////////////////////////////////////////
			////////////////////////////////////////////////////////////////////////////////////////////////


switch (input3)
   {
		case 0 : 
             {
			    output6=12 ;
                break;
	         }
		case 1 :
			{
				output6=10;
				break;
			}
		case 2 :
			{
				output6=1;
				break;
			}
		case 3 :
			{
				output6=15;
				break;
			}
		case 4 :
					
			{
				output6=10;
				break;
			}
		case 5:
			{
				output6=4;//////////////////////
				break;
			}
		case 6:
			{
				output6=15;
				break;
			}
		case 7:
			{
			    output6=2;
				break;
			}
		case 8:
			{
				output6=9;
				break;
			}
		case 9:
			{
				output6=7;
				break;
			}
		case 10:
			{
				output6=2;
				break;
			}
		case 11:
			{
				output6=12;
				break;
			}

		case 12:
			{
				output6=6;
				break;
			}
		case 13:
			{
				output6=9;
				break;
			}
		case 14:
			{
				output6=8;
				break;
			}
		case 15:
			{
				output6=5;
				break;
			}
		case 16:
			{
				output6=0;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output6=6;
				break;
			}
		case 18:
			{
				output6=13;
				break;
			}
		case 19:
			{
				output6=1;
				break;
			}
		case 20:
			{
				output6=3;
				break;

			}
		case 21:
			{
				output6=13;////////////////////
				break;
			}
		case 22:
			{
				output6=4;
				break;
			}
		case 23:
			{
				output6=14;
				break;
			}
		case 24:
			{
				output6=14;
				break;
			}
		case 25:
			{
				output6=0;
				break;
			}
		case 26:
			{
				output6=7;
				break;

			}
		case 27:
			{
				output6=11;
				break;
			}
		case 28:
			{
				output6=5;
				break;
			}
		case 29:
			{
				output6=3;
				break;
			}
		case 30:
			{
				output6=11;
				break;
			}
		case 31:
			{
				output6=8;
				break;
			}
		case 32:
			{
				output6=9;
				break;
			}
		case 33:
			{
				output6=4;
				break;
			}
		case 34 :
			{
				output6=14;
				break;
			}
		case 35:
			{
				output6=3;
				break;
			}
		case 36:
			{
				output6=15;
				break;
			}
		case 37:
			{
				output6=2;
				break;
			}
		case 38:
			{
				output6=5;
				break;
			}
		case 39:
			{
				output6=12;
				break;
			}
		case 40:
			{
				output6=2;
				break;
			}
		case 41:
			{
				output6=9;
				break;
			}
		case 42:
			{
				output6=8;
				break;
			}
		case 43:
			{
				output6=5;
				break;
			}

		case 44:
			{
				output6=12;
				break;
			}
		case 45:
			{
				output6=15;
				break;
			}
		case 46:
			{
				output6=3;
				break;
			}
		case 47:
			{
				output6=10;
				break;
			}
		case 48:
			{
				output6=7;
				break;
			}
		case 49:
			{
				output6=11;
				break;
			}
		case 50:
			{
				output6=0;
				break;
			}
		case 51:
			{
				output6=14;
				break;
			}
		case 52:
			{
				output6=4;
				break;
			}
		case 53:
			{
				output6=1;/////////////
				break;
			}
		case 54:
			{
				output6=10;
				break;
			}
		case 55:
			{
				output6=7;
				break;
			}
		case 56:
			{
				output6=1;
				break;
			}
		case 57:
			{
				output6=6;
				break;
			}
		case 58:
			{
				output6=13;
				break;
			}
		case 59:
			{
				output6=0;
				break;
			}
		case 60:
			{
				output6=11;
				break;
			}
		case 61:
			{
				output6=8;
				break;
			}
		case 62:
			{
				output6=6;
				break;
			}
		case 63:
			{
				output6=13;
				break;
			}

			}

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////// INPUT 7 /////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////



switch (input2)
   {
		case 0 : 
             {
			    output7=4 ;
                break;
	         }
		case 1 :
			{
				output7=13;
				break;
			}
		case 2 :
			{
				output7=11;
				break;
			}
		case 3 :
			{
				output7=0;
				break;
			}
		case 4 :
					
			{
				output7=2;
				break;
			}
		case 5:
			{
				output7=11;//////////////////////
				break;
			}
		case 6:
			{
				output7=14;
				break;
			}
		case 7:
			{
			    output7=7;
				break;
			}
		case 8:
			{
				output7=15;
				break;
			}
		case 9:
			{
				output7=4;
				break;
			}
		case 10:
			{
				output7=0;
				break;
			}
		case 11:
			{
				output7=9;
				break;
			}

		case 12:
			{
				output7=8;
				break;
			}
		case 13:
			{
				output7=1;
				break;
			}
		case 14:
			{
				output7=13;
				break;
			}
		case 15:
			{
				output7=10;
				break;
			}
		case 16:
			{
				output7=3;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output7=14;
				break;
			}
		case 18:
			{
				output7=12;
				break;
			}
		case 19:
			{
				output7=3;
				break;
			}
		case 20:
			{
				output7=9;
				break;

			}
		case 21:
			{
				output7=5;////////////////////
				break;
			}
		case 22:
			{
				output7=7;
				break;
			}
		case 23:
			{
				output7=12;
				break;
			}
		case 24:
			{
				output7=5;
				break;
			}
		case 25:
			{
				output7=2;
				break;
			}
		case 26:
			{
				output7=10;
				break;

			}
		case 27:
			{
				output7=15;
				break;
			}
		case 28:
			{
				output7=6;
				break;
			}
		case 29:
			{
				output7=8;
				break;
			}
		case 30:
			{
				output7=1;
				break;
			}
		case 31:
			{
				output7=6;
				break;
			}
		case 32:
			{
				output7=1;
				break;
			}
		case 33:
			{
				output7=6;
				break;
			}
		case 34 :
			{
				output7=4;
				break;
			}
		case 35:
			{
				output7=11;
				break;
			}
		case 36:
			{
				output7=11;
				break;
			}
		case 37:
			{
				output7=13;
				break;
			}
		case 38:
			{
				output7=13;
				break;
			}
		case 39:
			{
				output7=8;
				break;
			}
		case 40:
			{
				output7=12;
				break;
			}
		case 41:
			{
				output7=1;
				break;
			}
		case 42:
			{
				output7=3;
				break;
			}
		case 43:
			{
				output7=4;
				break;
			}

		case 44:
			{
				output7=7;
				break;
			}
		case 45:
			{
				output7=10;
				break;
			}
		case 46:
			{
				output7=14;
				break;
			}
		case 47:
			{
				output7=7;
				break;
			}
		case 48:
			{
				output7=10;
				break;
			}
		case 49:
			{
				output7=9;
				break;
			}
		case 50:
			{
				output7=15;
				break;
			}
		case 51:
			{
				output7=5;
				break;
			}
		case 52:
			{
				output7=6;
				break;
			}
		case 53:
			{
				output7=0;/////////////
				break;
			}
		case 54:
			{
				output7=8;
				break;
			}
		case 55:
			{
				output7=15;
				break;
			}
		case 56:
			{
				output7=0;
				break;
			}
		case 57:
			{
				output7=14;
				break;
			}
		case 58:
			{
				output7=5;
				break;
			}
		case 59:
			{
				output7=2;
				break;
			}
		case 60:
			{
				output7=9;
				break;
			}
		case 61:
			{
				output7=3;
				break;
			}
		case 62:
			{
				output7=2;
				break;
			}
		case 63:
			{
				output7=12;
				break;
			}

			}

//////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// INPUT 8 ///////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

switch (input1)
   {
		case 0 : 
             {
			    output8=13 ;
                break;
	         }
		case 1 :
			{
				output8=1;
				break;
			}
		case 2 :
			{
				output8=2;
				break;
			}
		case 3 :
			{
				output8=15;
				break;
			}
		case 4 :
					
			{
				output8=8;
				break;
			}
		case 5:
			{
				output8=13;//////////////////////
				break;
			}
		case 6:
			{
				output8=4;
				break;
			}
		case 7:
			{
			    output8=8;
				break;
			}
		case 8:
			{
				output8=6;
				break;
			}
		case 9:
			{
				output8=10;
				break;
			}
		case 10:
			{
				output8=15;
				break;
			}
		case 11:
			{
				output8=3;
				break;
			}

		case 12:
			{
				output8=11;
				break;
			}
		case 13:
			{
				output8=7;
				break;
			}
		case 14:
			{
				output8=1;
				break;
			}
		case 15:
			{
				output8=4;
				break;
			}
		case 16:
			{
				output8=10;///////////////////////////////////////
				break;
			}
		case 17:
			{
				output8=12;
				break;
			}
		case 18:
			{
				output8=9;
				break;
			}
		case 19:
			{
				output8=5;
				break;
			}
		case 20:
			{
				output8=3;
				break;

			}
		case 21:
			{
				output8=6;////////////////////
				break;
			}
		case 22:
			{
				output8=14;
				break;
			}
		case 23:
			{
				output8=11;
				break;
			}
		case 24:
			{
				output8=5;
				break;
			}
		case 25:
			{
				output8=0;
				break;
			}
		case 26:
			{
				output8=0;
				break;

			}
		case 27:
			{
				output8=14;
				break;
			}
		case 28:
			{
				output8=12;
				break;
			}
		case 29:
			{
				output8=9;
				break;
			}
		case 30:
			{
				output8=7;
				break;
			}
		case 31:
			{
				output8=2;
				break;
			}
		case 32:
			{
				output8=7;
				break;
			}
		case 33:
			{
				output8=2;
				break;
			}
		case 34 :
			{
				output8=11;
				break;
			}
		case 35:
			{
				output8=1;
				break;
			}
		case 36:
			{
				output8=4;
				break;
			}
		case 37:
			{
				output8=14;
				break;
			}
		case 38:
			{
				output8=1;
				break;
			}
		case 39:
			{
				output8=7;
				break;
			}
		case 40:
			{
				output8=9;
				break;
			}
		case 41:
			{
				output8=4;
				break;
			}
		case 42:
			{
				output8=12;
				break;
			}
		case 43:
			{
				output8=10;
				break;
			}

		case 44:
			{
				output8=14;
				break;
			}
		case 45:
			{
				output8=8;
				break;
			}
		case 46:
			{
				output8=2;
				break;
			}
		case 47:
			{
				output8=13;
				break;
			}
		case 48:
			{
				output8=0;
				break;
			}
		case 49:
			{
				output8=15;
				break;
			}
		case 50:
			{
				output8=6;
				break;
			}
		case 51:
			{
				output8=12;
				break;
			}
		case 52:
			{
				output8=10;
				break;
			}
		case 53:
			{
				output8=9;/////////////
				break;
			}
		case 54:
			{
				output8=13;
				break;
			}
		case 55:
			{
				output8=0;
				break;
			}
		case 56:
			{
				output8=15;
				break;
			}
		case 57:
			{
				output8=3;
				break;
			}
		case 58:
			{
				output8=3;
				break;
			}
		case 59:
			{
				output8=5;
				break;
			}
		case 60:
			{
				output8=5;
				break;
			}
		case 61:
			{
				output8=6;
				break;
			}
		case 62:
			{
				output8=8;
				break;
			}
		case 63:
			{
				output8=11;
				break;
			}

			}

//////////////////////////////////// Output evaluation //////////////////////////////////////////

			output = output1<<28 | output2<<24 | output3<<20 | output4<<16 | output5<<12 | output6<<8 | output7<<4 | output8 ;

					/*for(int s=0;s<8;s++)  
					{
						frame = 0;
						frame  = input & LONGBIT_64_6(s*6); // Fetching the frame 
						frame = frame>>(s*6);
		
						if(frame%2 == 0) // if the frame contain even number
						{
							if(frame <32)
							{
								row = 0;
								column = frame>>1;
							}
							else if(frame >= 32)
							{
								row = 2;
								column = (frame-32)>>1;
							}
						}
						else                          // if the frame contain odd number 
						{
							if(frame <33)
							{
								row = 1;
								column = frame>>1;
							}
							else if(frame >= 33)
							{
								row = 3;
								column = (frame-32)>>1;
							}
						}
					/////////////// assgning values into output ///////////////////////
					output |= Sbox[7-s][row][column]<<(4*s);
		
				}*/
				sOutput=output;

				////////////////////////////////////////////////////
				//last permutation in the F-function after s-box


				xorInput=0;
				//////////////////////////////////////////////////////////////////////
				/////////////////////////////////////////////////////////////////////
				xorInput|= ((sOutput&0x00010000))<<15;//bit no (16)
				xorInput|= ((sOutput&0x02020120))<<5;//bit no (25,17,8,5)
				xorInput|= ((sOutput&0x00001800))<<17;//bit no (12,11)
				xorInput|= ((sOutput&0x00000008))<<24;//bit no (3)
				xorInput|= ((sOutput&0x00100000))<<6;//bit no (20)
				xorInput|= ((sOutput&0x00000010))<<21;//bit no (4)
				xorInput|= ((sOutput&0x00008000))<<9;//bit no (15)
				xorInput|= ((sOutput&0x00000200))<<12;//bit no (9)
				xorInput|= ((sOutput&0x00000040))<<14;//bit no (6)
				xorInput|= ((sOutput&0x00004000))<<4;//bit no (14)
				xorInput|= ((sOutput&0x00000002))<<16;//bit no (1)
				xorInput|= ((sOutput&0x00000001))<<11;//bit no (0)
				xorInput|= ((sOutput&0x00000004))<<3;//bit no (2)
				xorInput|= ((sOutput&0x88000000))>>8;//bit no (31,27)
				xorInput|= ((sOutput&0x00442000))>>6;//bit no (22,18,13)
				xorInput|= ((sOutput&0x40800000))>>15;//bit no (30,23)
				xorInput|= ((sOutput&0x01000000))>>10;//bit no (24)
				xorInput|= ((sOutput&0x20000000))>>20;//bit no (29)
				xorInput|= ((sOutput&0x00080000))>>13;//bit no (19)
				xorInput|= ((sOutput&0x04000000))>>22;//bit no (26)
				xorInput|= ((sOutput&0x00000480))>>7;//bit no (10,7)
				xorInput|= ((sOutput&0x00200000))>>19;//bit no (21)
				xorInput|= ((sOutput&0x10000000))>>27;//bit no (28)
			
				//////////////////////////////////////////////////////////
				////xor to get new left and right data 
			
			
				temp=xorInput^leftData;
				leftData=rightData;
				rightData=temp;



					
			}
			///////////////////////////////////////////////////////////////////// swap///////////////////////////////////////////////////////////
		
				long long dataToInversePermutation=0;
				temp=0;
				temp=(long long)leftData;
				leftData=rightData;
				rightData=temp;

				dataToInversePermutation|=((((long long)leftData)<<32)|(((long long)rightData) &0x00000000FFFFFFFF));
		
			///////////////////////////////////////////////////////////////////// Inverse Intial permutation/////////////////////////////////////
		
			int iIPCounter;
			long long dataOutput;
			dataOutput=0;
			dataOutput|= ((dataToInversePermutation&0x0000040000200000))<<0;
			dataOutput|= ((dataToInversePermutation&0x0002000010000040))<<3;
			dataOutput|= ((dataToInversePermutation&0x0100000400002000))<<6;
			dataOutput|= ((dataToInversePermutation&0x0000020000100000))<<9;
			dataOutput|= ((dataToInversePermutation&0x0001000008000020))<<12;
			dataOutput|= ((dataToInversePermutation&0x0000000200001000))<<15;
			dataOutput|= ((dataToInversePermutation&0x0000010000080000))<<18;
			dataOutput|= ((dataToInversePermutation&0x0000000004000010))<<21;
			dataOutput|= ((dataToInversePermutation&0x0000000100000800))<<24;
			dataOutput|= ((dataToInversePermutation&0x0000000000040000))<<27;
			dataOutput|= ((dataToInversePermutation&0x0000000002000008))<<30;
			dataOutput|= ((dataToInversePermutation&0x0000000000000400))<<33;
			dataOutput|= ((dataToInversePermutation&0x0000000000020000))<<36;
			dataOutput|= ((dataToInversePermutation&0x0000000001000004))<<39;
			dataOutput|= ((dataToInversePermutation&0x0000000000000200))<<42;
			dataOutput|= ((dataToInversePermutation&0x0000000000010000))<<45;
			dataOutput|= ((dataToInversePermutation&0x0000000000000002))<<48;
			dataOutput|= ((dataToInversePermutation&0x0000000000000100))<<51;
			dataOutput|= ((dataToInversePermutation&0x0000000000000001))<<57;
			///////////////////////////////////////////////////////////////////////////
			dataOutput|= ((dataToInversePermutation&0x0200000800004000))>>3;
			dataOutput|= ((dataToInversePermutation&0x0004000020000080))>>6;
			dataOutput|= ((dataToInversePermutation&0x0000080000400000))>>9;
			dataOutput|= ((dataToInversePermutation&0x0400001000008000))>>12;
			dataOutput|= ((dataToInversePermutation&0x0008000040000000))>>15;
			dataOutput|= ((dataToInversePermutation&0x0000100000800000))>>18;
			dataOutput|= ((dataToInversePermutation&0x0800002000000000))>>21;
			dataOutput|= ((dataToInversePermutation&0x0010000080000000))>>24;
			dataOutput|= ((dataToInversePermutation&0x0000200000000000))>>27;
			dataOutput|= ((dataToInversePermutation&0x1000004000000000))>>30;
			dataOutput|= ((dataToInversePermutation&0x0020000000000000))>>33;
			dataOutput|= ((dataToInversePermutation&0x0000400000000000))>>36;
			dataOutput|= ((dataToInversePermutation&0x2000008000000000))>>39;
			dataOutput|= ((dataToInversePermutation&0x0040000000000000))>>42;
			dataOutput|= ((dataToInversePermutation&0x0000800000000000))>>45;
			dataOutput|= ((dataToInversePermutation&0x4000000000000000))>>48;
			dataOutput|= ((dataToInversePermutation&0x0080000000000000))>>51;
			dataOutput|= ((dataToInversePermutation&0x8000000000000000))>>57;
			/////////////////////////////////////////////////////////////////
			/// write data to cipher text
			Write64Bit2(plainTextFile,&dataOutput,completeBlockCount,&count1);
		

		}//Finished reading+

		printf("\n >>Decryption completed successfully !");


	}



	////////////////Niether encryption nor decryption/////////////////////////////////////////////////////////////////////////////
	else
	{
		printf("\nInvalid Operation.\n");
		return 0;
	}


	long finishTime = clock();

	printf("%d" ,finishTime-startTime);

	fclose(keyFile);
	fclose(plainTextFile);
	fclose(pCipherTextFile);

	return 1;
}