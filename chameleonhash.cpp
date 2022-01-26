//
// Created by qyxie on 25/1/2022.
//
#include<cryptopp/eccrypto.h>
#include<cryptopp/osrng.h>
#include<cryptopp/nbtheory.h>
#include<cryptopp/cryptlib.h>
#include<cryptopp/sha3.h>
#include<cryptopp/algebra.h>
#include<time.h>
#include<iostream>

struct CHPublicKey{
    CryptoPP::Integer p;
    CryptoPP::Integer q;
    CryptoPP::Integer g;
    CryptoPP::Integer y;
};

struct CHSecretKey{
    CryptoPP::Integer sk;
};

// TODO Keygen
std::pair<CHPublicKey, CHSecretKey> Keygen(int delta, int n_bits){
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::Integer p, q;
    CryptoPP::PrimeAndGenerator pg(1, prng, 1024);

    p = pg.Prime();
    // q = (p - 1) / 2
    q = pg.SubPrime();

    // g [0, p]  BigInteger
    // g = g ^ 2 % p
    CryptoPP::Integer g(prng, 0, p);
    g = a_exp_b_mod_c(g, 2, p);

    // sk [0, q] BigInteger
    CryptoPP::Integer sk(prng, 0, q);
    // y = g ^ sk % p
    CryptoPP::Integer y = a_exp_b_mod_c(g, sk, p);

    CHPublicKey PK{p, q, g, y};
    CHSecretKey SK{sk};

    return std::make_pair(PK, SK);
}

// TODO hash
// CH=g^m*h^r mod p
CryptoPP::Integer chameleonHash(std::string msg, CHPublicKey pk, CHSecretKey sk, CryptoPP::Integer r){
    std::string digest;
    CryptoPP::SHA3_256 hash;
    hash.Update((const CryptoPP::byte*)msg.data(), msg.size());
    digest.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte*)&digest[0]);

    CryptoPP::Integer m(digest.c_str());

    CryptoPP::Integer ch_digest;

    CryptoPP::Integer x = m + sk.sk * r;

    ch_digest = a_times_b_mod_c(pk.g, x, pk.p);

    return ch_digest;
}

// TODO forge
// CH=g^m*h^r =g^m'*h^r' mod p，可得m+rx=m'+r'x mod q，继而可计算出r'=(m-m'+rx)*x^(-1) mod q
CryptoPP::Integer forge(std::string ori_msg, std::string new_msg, CHPublicKey pk, CHSecretKey sk, CryptoPP::Integer r){
    CryptoPP::Integer new_r;

    std::string ori_digest;
    CryptoPP::SHA3_256 ori_hash;
    ori_hash.Update((const CryptoPP::byte*)ori_msg.data(), ori_msg.size());
    ori_digest.resize(ori_hash.DigestSize());
    ori_hash.Final((CryptoPP::byte*)&ori_digest[0]);

    std::string new_digest;
    CryptoPP::SHA3_256 new_hash;
    new_hash.Update((const CryptoPP::byte*)new_msg.data(), new_msg.size());
    new_digest.resize(new_hash.DigestSize());
    new_hash.Final((CryptoPP::byte*)&new_digest[0]);

    CryptoPP::Integer m(ori_digest.c_str());
    CryptoPP::Integer new_m(new_digest.c_str());

    new_r = (m - new_m + r * sk.sk) / sk.sk % pk.q;

    return new_r;
}

int main(int argc, const char* argv[]){
    auto [pk, sk] = Keygen(1, 1024);
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::Integer r(prng, 0, pk.q);

    std::string s = "yes";
    clock_t start=clock();
    CryptoPP::Integer ch = chameleonHash(s, pk, sk, r);
    clock_t finish=clock();
    std::cout << "chameleon hash: " << ch << std::endl;
    double Times = (double)(finish-start) / CLOCKS_PER_SEC;
    std::cout << "generation time: " << Times << "s" << std::endl;

    std::string new_s = "no";
    clock_t forge_start=clock();
    CryptoPP::Integer new_r = forge(s, new_s, pk, sk, r);
    clock_t forge_finish=clock();
    std::cout << "r: " << r << std::endl;
    std::cout << "forge: " << new_r << std::endl;
    double forge_Times = (double)(forge_finish-forge_start) / CLOCKS_PER_SEC;
    std::cout << "forge time: " << forge_Times << "s" << std::endl;

    return 0;
}

