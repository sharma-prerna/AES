//AES ENCRYPTION AND DECRYPTION
#include<stdio.h>
#include<stdint.h>
#include<stdbool.h>
#include<stdlib.h>
#define left_rot(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))
void encryption(uint8_t inp[4][4],uint8_t key[4][4],uint8_t sbox[16][16]);
void decryption(uint8_t inp[4][4],uint8_t key[4][4],uint8_t sbox[16][16],uint8_t Invsbox[16][16]);
void get_input(uint8_t temp[4][4]);
void s_box(uint8_t gtemp[16][16]);
void Invs_box(uint8_t gtemp[16][16]);
void Add_round_key(uint8_t state[4][4],uint8_t temp[4][44],int n);
void extension_of_key(uint8_t key[4][4],uint8_t temp[4][44],uint8_t sbox[16][16]);
void print(uint8_t state[4][4]);
void sub_bytes(uint8_t temp[4],uint8_t sbox[16][16]);
void shift_rows(uint8_t state[4][4]);
void Invshift_rows(uint8_t state[4][4]);
void mix_cols(uint8_t state[4][4]);
void Invmix_cols(uint8_t state[4][4]);
uint8_t multiply(uint8_t x,int y);
void rotate_l(uint8_t temp[4],int n);
uint8_t hex_to_deci(char* str,int k);
uint8_t Rcon(int n);
uint8_t extended_key[4][44],sbox[16][16],Invsbox[16][16];
int main()
{
	int con=0;
	char dec;
	s_box(sbox);
	Invs_box(Invsbox);
	uint8_t input[4][4],key[4][4];
	printf("\n-----------------------WELCOME TO ADVANCED ENCRYPTION STANDARD :)---------------------\n\n");
	do{
		printf("--------------------ENTER E OR e TO ENCRYPT AND D or d TO DECRYPT---------------------\n");
		scanf("%c",&dec);
		getchar();						//consuming newline char
		if(dec=='E'||dec=='e')
		{
				printf("------------------Enter input of 128 bits----------------\n");
				get_input(input);				// taking input
				printf("---------------Enter the key of 128 bits-----------------\n"); 
				get_input(key); 				//taking input of key	
				encryption(input,key,sbox);
	    }       
		else if(dec=='D'||dec=='d')
		{
				printf("------------------Enter input of 128 bits----------------\n");
				get_input(input);				// taking input
				printf("---------------Enter the key of 128 bits-----------------\n"); 
				get_input(key);					//taking input of key 	
				decryption(input,key,sbox,Invsbox);	
		}
		else
		printf("\n-------------------------PLEASE! ENTER THE CORRECT INPUT------------------\n");
		printf("\n-------------------ENTER 0 TO CONITNUE-------------------\n");
		scanf("%d",&con);
		getchar();     //consuming newline char	
	}while(con==0);
	printf("\n----------------THANK YOU FOR USING OUR SERVICE, HAVE A NICE DAY :)-------------------\n");
	return 0;
}
void encryption(uint8_t input[4][4],uint8_t key[4][4],uint8_t sbox[16][16])
{
	
	int i,j,k;	
	printf("INPUT IS :\t\t");
	print(input);
	printf("KEY IS :\t\t");
	print(key);
	extension_of_key(key,extended_key,sbox);
	Add_round_key(input,extended_key,0);
	printf("AFTER ADDING KEY :\t");
	print(input);
	for(k=1;k<10;k++)
	{
		printf("----------------------------------ROUND %d-------------------------------\n\n",k);
		for(i=0;i<4;i++)
	   		sub_bytes(input[i],sbox);
	   	printf("AFTER SUBSTITUTION :\t");
	   	print(input);
		shift_rows(input);
		printf("AFTER SHIFTING ROWS :\t");
		print(input);
		mix_cols(input);
		printf("AFTER MIXING COLS :\t");
		print(input);
		Add_round_key(input,extended_key,k);
		printf("AFTER ADDING KEY :\t");
		print(input);
	}
	printf("\n----------------------------------ROUND %d-------------------------------\n",k);
	for(i=0;i<4;i++)
 		sub_bytes(input[i],sbox);
 	printf("AFTER SUBSTITUTION :\t");
	print(input);
	shift_rows(input);
	printf("AFTER SHIFTING ROWS :\t");
	print(input);
	Add_round_key(input,extended_key,10);
	printf("ENCRYPTED OUTPUT IS :\t");
	print(input);
}
void decryption(uint8_t input[4][4],uint8_t key[4][4],uint8_t sbox[16][16],uint8_t Invsbox[16][16])
{
	int i,j,k=0;
	printf("INPUT IS :\t\t");
	print(input);
	printf("KEY IS :\t\t");
	print(key);
	extension_of_key(key,extended_key,sbox);
	Add_round_key(input,extended_key,10);
	printf("AFTER ADDING KEY :\t");
	print(input);
	for(k=9;k>0;k--)
	{
		printf("\n--------------------------------ROUND %d----------------------------------\n\n",(10-k));
		Invshift_rows(input);
		printf("AFTER SHIFTING ROWS :\t");
		print(input);
		//substitution
		for(i=0;i<4;i++)
	   	{
			sub_bytes(input[i],Invsbox);
		}
	   	printf("SUBSTITUTION OF BYTES :\t");
	   	print(input);
	   	Add_round_key(input,extended_key,k);
		printf("AFTER ADDING KEY :\t");
		print(input);
		Invmix_cols(input);
		printf("AFTER MIXING COLOUMNS :\t");
		print(input);
	}
	printf("\n-------------------------ROUND 10----------------------\n\n");
	Invshift_rows(input);
	printf("AFTER SHIFTING ROWS :\t");
	print(input);
	for(i=0;i<4;i++)
 		sub_bytes(input[i],Invsbox);
 	printf("AFTER SUBSTITUTION :\t");
 	print(input);
	Add_round_key(input,extended_key,0);
	printf("AFTER ADDING KEY :\t");
	print(input);
	printf("DECRYPTED OUTPUT IS :\t");
	print(input);	
}
void s_box(uint8_t sbox[16][16])
{
	int i=0,j=0,k=0;
	uint8_t* box;
	box=(uint8_t*)calloc(256,sizeof(uint8_t));
	uint8_t a=1,b=1;	// a is input and b is its multiplicative inverse
	do {
		a  = a ^ (a << 1) ^ (a & 0x80 ? 0x1B : 0);
		b ^= b << 1;
		b ^= b << 2;
		b ^= b << 4;
		b ^= b & 0x80 ? 0x09 : 0;
		uint8_t affine = b ^ left_rot(b, 1) ^ left_rot(b, 2) ^ left_rot(b, 3) ^ left_rot(b, 4);
		box[a]= affine^0x63;
		
	} while (a!=1);
	box[0]=0x63;
	k=0;
	for(i=0;i<16;i++)
	{
		for(j=0;j<16;j++)
		{
			sbox[i][j]=box[k];
			k++;
		}
	}
	free(box);
}
void Invs_box(uint8_t Invsbox[16][16])
{
	int i=0,row=0,col=0;
	uint8_t p=1,q=1;
	uint8_t* table;
	table=(uint8_t*)calloc(256,sizeof(uint8_t));
	do{
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;
		table[p]=q;
	}while(p!=1);
	p=1;
	for(i=0;i<256;i++)
	{
		if(i%16==0&&i>0)
		{
			row++;
			col=0;
		}
		//INVERSE AFFINE TRANSFORMATION
		p=left_rot(i,1) ^ left_rot(i,3) ^ left_rot(i,6) ^ 0x05;
		q= table[p];
		Invsbox[row][col]=q;
		col++;
	}
	free(table);
}
void extension_of_key(uint8_t key[4][4],uint8_t extended_key[4][44],uint8_t sbox[16][16])
{
	int i,j;
	uint8_t temp[4],rcon;
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
			extended_key[i][j]=key[i][j];
	}
	for(i=4;i<44;i++)
	{
		for(j=0;j<4;j++)
			temp[j]=extended_key[j][i-1];
		if(i%4==0)
		{
			rcon=Rcon((i/4)-1);
			rotate_l(temp,1);
			sub_bytes(temp,sbox);
			temp[0]=temp[0]^rcon;
		}
		for(j=0;j<4;j++)
		{
			extended_key[j][i]=(extended_key[j][i-4]^temp[j]);
		}
	}
}
void Add_round_key(uint8_t inp[4][4],uint8_t key[4][44],int r)
{
	int i=0,j=0;
//	printf("\nROUND KEY\t");
//	for(i=0;i<4;i++)
//	{
//		for(j=0;j<4;j++)
//		{
//			printf("%02x ",key[j][(4*r)+i]);
//		}
//	}
	printf("\n");
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			inp[j][i]^=key[j][(4*r)+i];
		}
	}
}
uint8_t Rcon(int x)
{
	int i=0;
	uint8_t temp=01;
	if(x==0)
		return temp;
	for(i=1;i<=x;i++)
	{
		temp=multiply(temp,2);
	}
	return temp;	
}
void sub_bytes(uint8_t inp[4],uint8_t box[16][16])
{
	int x,y,i=0,j=0;
	for(i=0;i<4;i++)
	{
			y=inp[i]%16;
			x=inp[i]/16;
			inp[i]=box[x][y];
	}
}
void shift_rows(uint8_t input[4][4])
{
	int i,j,temp,k;
	for(i=1;i<4;i++)
		rotate_l(input[i],i);
}
void Invshift_rows(uint8_t input[4][4])
{
	int i,j,temp,k;
	for(k=1;k<=3;k++)
	{
	for(j=1;j<=k;j++)
	{
		temp=input[k][3];
		for(i=3;i>=1;i--)
		{
			input[k][i]=input[k][i-1];
		}
		input[k][0]=temp;
	}
	}
}
void mix_cols(uint8_t input[4][4])
{
	uint8_t word[4];
	int i=0,j,k;
	for(i=0;i<4;i++)
	{ 
		word[0]=multiply(input[0][i],2)^multiply(input[1][i],3)^input[2][i]^input[3][i];
		word[1]=multiply(input[1][i],2)^multiply(input[2][i],3)^input[3][i]^input[0][i];
		word[2]=multiply(input[2][i],2)^multiply(input[3][i],3)^input[0][i]^input[1][i];
		word[3]=multiply(input[3][i],2)^multiply(input[0][i],3)^input[1][i]^input[2][i];
		for(j=0;j<4;j++)
			input[j][i]=word[j];
	}
}
void Invmix_cols(uint8_t input[4][4])
{
	uint8_t word[4];
	int i=0,j,k;
	for(i=0;i<4;i++)
	{ 
		word[0]=multiply(input[0][i],14)^multiply(input[1][i],11)^multiply(input[2][i],13)^multiply(input[3][i],9);
		word[1]=multiply(input[1][i],14)^multiply(input[2][i],11)^multiply(input[3][i],13)^multiply(input[0][i],9);
		word[2]=multiply(input[2][i],14)^multiply(input[3][i],11)^multiply(input[0][i],13)^multiply(input[1][i],9);
		word[3]=multiply(input[3][i],14)^multiply(input[0][i],11)^multiply(input[1][i],13)^multiply(input[2][i],9);
		for(j=0;j<4;j++)
			input[j][i]=word[j];
	}
}
void rotate_l(uint8_t word[4],int shift)
{
	int i,temp,j;
	for(j=1;j<=shift;j++)
	{
		temp=word[0];
		for(i=0;i<3;i++)
		{
			word[i]=word[i+1];
		}
		word[i]=temp;
	}
}
//multiplication of two polynomials or bytes in Galois field with modulo {01}{1b}
uint8_t multiply(uint8_t inp,int x)
{
	int flag=2;
	uint8_t temp=inp;
	if(x==1)
		return inp;
	do
	{
		if(temp&0x80)
		{
			temp=temp<<1;
			 temp^=0x1B;
		}
		else
		{
			temp=temp<<1;
		}
		flag=flag*2;
	}while(flag<=x);
	x-= (flag/2);
	if(x>=1)
	{
		temp^=multiply(inp,x);
	}
	return temp;
}

void print(uint8_t input[4][4])
{
	int i=0,j=0;
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
			printf(" %02x",input[j][i]);
	//	printf("\n");
	}
	printf("\n");
}
void get_input(uint8_t inp[4][4])
{
	char st[100];
	gets(st);
	int k=0;
	int i,j;
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
		{
			inp[j][i]=hex_to_deci(st,k);
			k=k+2;
		}
	} 
}
uint8_t hex_to_deci(char* st,int k)
{
	uint8_t temp;
		if(st[k]-'0'>9)
			{
				temp=st[k+0]-'a';
				temp+=10;
			}
			else
				temp=st[k+0]-'0';
			temp*=16;
			if(st[k+1]-'0'>9)
			{
				temp+=st[k+1]-'a';
				temp+=10;
			}
			else
				temp+=st[k+1]-'0';
	return temp;
}

//input: 00112233445566778899aabbccddeeff
//0 17 34 51 68 85 102 119 136 153 170 187 204 221 238 255

//key: 000102030405060708090a0b0c0d0e0f
//0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15

 //output: 69c4e0d86a7b0430d8cdb78070b4c55a
 //105 196 224 216 106 123 4 48 216 205 183 128 112 180 197 90
 
 //INPUT 2
 //3243f6a8885a308d313198a2e0370734 
//50 67 246 168 136 90 48 141 49 49 152 162 224 55 7 52
// 2C÷¿êZ0ì11ÿóa7 4

//key
//2b7e151628aed2a6abf7158809cf4f3c
//43 126 21 22 40 174 210 166 171 247 21 136 9 207 79 60 
//+~\"\"(«-ª½˜\"ê	-O<

//3925841d02dc09fbdc118597196a0b32
//57 37 132 29 2 220 9 251 220 17 133 151 25 106 11 50
