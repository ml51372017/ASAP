
#include "stdafx.h"

#include <ctime>
#include <iostream>
#include <windows.h>
#include <math.h>

#include <stdio.h>
#include <fstream>
#include <sstream>

#include "randpool.h"
#include "rsa.h"

#include "hex.h"
#include "modes.h"
#include "files.h"

#include "sha.h"
#include "secblock.h"
#include "sha3.h"

#include <vector>

#include <cstring>
#include <sys/timeb.h>
#include "big.h"
#include "ecn.h"
#include "zzn.h"
#include "zzn2.h"
#include "bilinearmap.h"

using namespace std;
using namespace CryptoPP;

#pragma comment(lib, "cryptlib.lib")
 
#define Num 10
#define M   1000

Miracl precision(10000,0);

struct Suppnode
{
	int PID;
	string Supp;
	string K;
	string price;
	ECn sig_1, sig_2;
	struct Suppnode *next;

	Suppnode()
	{
		memset(this,0,sizeof(Suppnode));
	}
};

struct Hashnode
{
	string hashvalue;
	Hashnode *c1, *c2;
	struct Suppnode *next;

	Hashnode()
	{
		memset(this,0,sizeof(Hashnode)); 
	}
};

struct Arraynode
{
	bool identification;
	int mod;
	struct Hashnode *next;

	Arraynode()
	{
		memset(this,0,sizeof(Arraynode)); 
	}
};

void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed); 
string RSAEncryptString(const char *pubFilename, const char *seed, const char *message); 
string RSADecryptString(const char *privFilename, const char *ciphertext);
RandomPool & GlobalRNG();

void InsertHashmap(int loc, string temp_hash, int temp_mod, Arraynode arraynode[], string Supp, ECn sig1[], ECn sig2[]);//插入Park
string Search(string Park, Arraynode arraynode[]);

int _tmain(int argc, _TCHAR* argv[])
{
	ofstream outfile("result.txt");

	cout<<"Number of user: "<<Num<<endl;
	outfile<<"Number of user: "<<Num<<endl;

	int i = 0;
	int ID = 1234;
	cout<<"Byte of ID: "<<sizeof(ID)<<endl;
	string tt = "20160720";
	cout<<"Byte of time: "<<sizeof(tt)<<endl;

	LARGE_INTEGER MnFreq;

	ECn g;
    ZZn2 cube;
    Big s,p,q,t,n,cof;
	
	miracl *mip = &precision;
	mip->IOBASE = 16;

	
	
	q = pow((Big)2,159)+pow((Big)2,17)+1;
	cout << "q= " << q << endl;
	t = (pow((Big)2,PBITS)-1)/(2*q);
    s = (pow((Big)2,PBITS-1)-1)/(2*q);

	forever
    {
        n = rand(t);
        if (n<s) continue;
        p = 2*n*q-1;
        if(p%24!=11) continue;
        if(prime(p)) break;
    }
    
	cof=2*n; 

    ecurve(0, 1, p, MR_PROJECTIVE);

	forever
    {
        cube = pow(randn2(),(p+1)/3);
        cube = pow(cube,p-1);
        if (!cube.isunity()) break;
    }
	

    if (!(cube*cube*cube).isunity())
    {
        cout << "sanity check failed" << endl;
        exit(0);
    }

	forever
    {
        while (!g.set(randn())) ;
        g*=cof;
        if (!g.iszero()) break;
    }

/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////


	ECn X, Y, U, Tau, Temp;
	Big tau = rand(q);
	Tau = tau*g;

	ZZn2 R;

	ECn sig1[Num];

	

	Big x = rand(q);
	X = x*g;
	Big y = rand(q);
	Y = y*g;

	for(i=0;i<Num;i++)
	{
		Big u = rand(q);
		U = u*g;
		sig1[i] = U;
		Temp = y*Tau;
		Temp +=  X;
		Temp = u * Temp;
		ecap(U, Y, q, cube, R);
	}

/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

	char priKey[128] = {0};
	char pubKey[128] = {0};
	char seed[2048] = {0};

	char priKey1[128] = {0};
	char pubKey1[128] = {0};

	char priKey2[128] = {0};
	char pubKey2[128] = {0};

	strcpy(priKey, "pri");
	strcpy(pubKey, "pub");
	strcpy(seed, "seed"); 
	GenerateRSAKey(2048, priKey, pubKey, seed);
	
	strcpy(priKey1, "pri1");
	strcpy(pubKey1, "pub1");
	GenerateRSAKey(2048, priKey1, pubKey1, seed);
		
	strcpy(priKey2, "pri2");
	strcpy(pubKey2, "pub2");
	GenerateRSAKey(2048, priKey2, pubKey2, seed);
	

	string temp_v;
	stringstream temp_vv(temp_v);
	string V[Num];
	for(i=0;i<Num;i++)//passed
	{
		temp_vv << rand()%10000;
		V[i] = temp_vv.str();
		temp_vv.str("");
	}

	SHA256 sha_coupon;
	char* Digest_coupon = new char[28];

	string Report[Num];
	char mtemp[2048];
	
	for(i=0;i<Num;i++)
	{
		sha_coupon.CalculateDigest((byte*)Digest_coupon, (const byte *)V[i].c_str(), V[i].size());//算hash值
		strcpy(mtemp, "1");
		Report[i] = RSAEncryptString(pubKey, seed, mtemp);
		Report[i] = RSADecryptString(priKey, Report[i].c_str());
		strcpy(mtemp, "2");
		Report[i] = RSAEncryptString(pubKey1, seed, mtemp);
		Report[i] = RSADecryptString(priKey1, Report[i].c_str());
		strcpy(mtemp, "3");
		Report[i] = RSAEncryptString(pubKey2, seed, mtemp);
	    Report[i] = RSADecryptString(priKey2, Report[i].c_str());
	}
	
	string Supp[Num];
	string temp_s;
	stringstream ss(temp_s);
	for(i=0;i<Num;i++)
	{
		ss << rand()%10000;
		Supp[i] = ss.str();
		ss.str("");
	}
	
	Arraynode arraynode[M];
	for(i=0;i<M;i++)
	{
		arraynode[i].identification = 0;
		arraynode[i].mod = 0;
		arraynode[i].next = NULL;
	}

	SHA256 sha_Supp;
	char* Digest_Supp = new char[28];
	
	string temp_hash;
	int temp_mod;
	
	for(i=0;i<Num;i++)
	{
		sha_Supp.CalculateDigest((byte*)Digest_Supp, (const byte *)Supp[i].c_str(), Supp[i].size());
		temp_hash = Digest_Supp;
		temp_mod = (*((unsigned short*)temp_hash.c_str())&0xffff) % M;
		InsertHashmap(i, temp_hash, temp_mod, arraynode, Supp[i], sig1, sig1);
	}
	
	
	getchar();
	return 0;
}


void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed) 
{ 
       RandomPool randPool; 
       randPool.Put((byte *)seed, strlen(seed)); 
  
       RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength); 
       HexEncoder privFile(new FileSink(privFilename)); 
       priv.DEREncode(privFile); 
       privFile.MessageEnd(); 
  
       RSAES_OAEP_SHA_Encryptor pub(priv); 
       HexEncoder pubFile(new FileSink(pubFilename)); 
       pub.DEREncode(pubFile); 
       pubFile.MessageEnd(); 
} 


string RSAEncryptString(const char *pubFilename, const char *seed, const char *message) 
{ 
       FileSource pubFile(pubFilename, true, new HexDecoder); 
       RSAES_OAEP_SHA_Encryptor pub(pubFile); 
  
       RandomPool randPool; 
       randPool.Put((byte *)seed, strlen(seed)); 
  
       string result; 
       StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result)))); 
       return result; 
}


string RSADecryptString(const char *privFilename, const char *ciphertext) 
{ 
	FileSource privFile(privFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor priv(privFile); 

	string result; 
	StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result)))); 
	return result;
} 


RandomPool & GlobalRNG() 
{ 
       static RandomPool randomPool; 
       return randomPool; 
}

void InsertHashmap(int loc, string temp_hash, int temp_mod, Arraynode arraynode[], string Supp, ECn sig1[], ECn sig2[])
{
	if(arraynode[temp_mod].next == NULL)
	{
		arraynode[temp_mod].identification = 1;
		arraynode[temp_mod].mod = temp_mod;
		Hashnode *h = new Hashnode;
		h->hashvalue = temp_hash;
		h->c1 = NULL;
		h->c2 = NULL;
		Suppnode *S = new Suppnode;
		S->PID = temp_mod;
		S->Supp = Supp;
		S->K = "1234";
		S->price = "25y/h";
		S->sig_1 = sig1[loc];
		S->sig_2 = sig2[loc];
		S->next = NULL;
		h->next = S;
		arraynode[temp_mod].next = h;
		return ;
	}
	
	else
	{
		Hashnode *h = arraynode[temp_mod].next;
				
		while(h!=NULL)
		{
			if(h->hashvalue>temp_hash && h->c1!=NULL)
			{
				h = h->c1;
			}
			else if(h->hashvalue<temp_hash && h->c2!=NULL)
			{
				h = h->c2;
			}
			
			if(h->hashvalue == temp_hash)
			{
				Suppnode *S = new Suppnode;
				S->PID = temp_mod;
				S->Supp = Supp;
				S->K = "1234";
				S->price = "25y/h";
				S->sig_1 = sig1[loc];
				S->sig_2 = sig2[loc];
				S->next = h->next;
				h->next = S;
				return ;
			}
			if(h->c1==NULL && h->hashvalue>temp_hash)
			{
				Hashnode *hh = new Hashnode;
				hh->hashvalue = temp_hash;
				hh->c1 = NULL;
				hh->c2 = NULL;
				Suppnode *S = new Suppnode;
				S->PID = temp_mod;
				S->Supp = Supp;
				S->K = "1234";
				S->price = "25y/h";
				S->sig_1 = sig1[loc];
				S->sig_2 = sig2[loc];
				S->next = NULL;
				//链接
				hh->next = S;
				h->c1 = hh;
				return ;
			}
			if(h->c2==NULL && h->hashvalue<temp_hash)
			{
				Hashnode *hh = new Hashnode;
				hh->hashvalue = temp_hash;
				hh->c1 = NULL;
				hh->c2 = NULL;
				Suppnode *S = new Suppnode;
				S->PID = temp_mod;
				S->Supp = Supp;
				S->K = "1234";
				S->price = "25y/h";
				S->sig_1 = sig1[loc];
				S->sig_2 = sig2[loc];
				S->next = NULL;
				//链接
				hh->next = S;
				h->c2 = hh;
				return ;
			}
		}
	}
}

string Search(string Park, Arraynode arraynode[])
{
	string ParkingResult = "Sorry, spots not available.";

	SHA256 sha_Park;
	char* Digest_Park = new char[28];
	string temp_hash_Park;
	int temp_mod_Park;

	sha_Park.CalculateDigest((byte*)Digest_Park, (const byte *)Park.c_str(), Park.size());
	temp_hash_Park = Digest_Park;
	temp_mod_Park = (*((unsigned short*)temp_hash_Park.c_str())&0xffff) % M;

	if(arraynode[temp_mod_Park].identification == 0)
	{
		return ParkingResult;
	}
	
	Hashnode *h = arraynode[temp_mod_Park].next;
	while(h!=NULL)
	{
		if(h->hashvalue == temp_hash_Park)
		{
			ParkingResult = h->next->Supp;
			return ParkingResult;
		}
		else if(h->hashvalue > temp_hash_Park)
		{
			h = h->c1;
		}
		else
		{
			h = h->c2;
		}
	}
	return ParkingResult;
}