//
// Created by qyxie on 25/1/2022.
//
#include<cryptopp/eccrypto.h>
#include<cryptopp/osrng.h>
#include<cryptopp/nbtheory.h>
#include<iostream>

struct CHPublicKey{
    CryptoPP::Integer p;
    CryptoPP::Integer q;
    CryptoPP::Integer g;
    CryptoPP::Integer y;
};

struct CHSecretKey{
    CHPublicKey pk;
    CryptoPP::Integer sk;
    CryptoPP::Integer InvMod_q;
};

// TODO Keygen
CryptoPP::Integer Keygen(int delta, int n_bits){
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::Integer p, q, g;
    CryptoPP::PrimeAndGenerator pg(1, prng, 1024);

    p = pg.Prime();
    q = pg.SubPrime();
    return p;
}

// TODO hash

// TODO forge

int main(int argc, const char* argv[]){
    CryptoPP::Integer p = Keygen(1, 1024);
    std::cout << "p: " << p << std::endl;
    return 0;
}

