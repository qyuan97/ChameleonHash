//
// Created by qyxie on 04/07/2022.
//

#include<cryptopp/eccrypto.h>
#include<cryptopp/osrng.h>
#include<cryptopp/nbtheory.h>
#include<cryptopp/cryptlib.h>
#include<cryptopp/sha3.h>
#include<cryptopp/algebra.h>
#include <cryptopp/hex.h>
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

std::pair<CHPublicKey, CHSecretKey> Keygen(int delta, int n_bits){
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::Integer p, q;
    CryptoPP::PrimeAndGenerator pg(1, prng, 256);

    p = pg.Prime();
    // q = (p - 1) / 2
    q = pg.SubPrime();

    // g [0, p]  BigInteger
    // g = g ^ 2 % p
    CryptoPP::Integer Two(2);
    CryptoPP::Integer g(prng, 0, p);
    g = a_exp_b_mod_c(g, Two, p);

    // sk [0, q] BigInteger
    CryptoPP::Integer sk(prng, 0, q);

    // y = g ^ sk % p
    CryptoPP::Integer y = a_exp_b_mod_c(g, sk, p);

    CHPublicKey PK{p, q, g, y};
    CHSecretKey SK{sk};

    return std::make_pair(PK, SK);
}

// CH=g^m*h^r mod p
CryptoPP::Integer chameleonHash(std::string msg, CHPublicKey pk, CHSecretKey sk, CryptoPP::Integer r){
    std::string digest;
    std::string hex_digest;

    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex_digest));
    CryptoPP::SHA3_256 hash;
    hash.Update((const CryptoPP::byte*)msg.data(), msg.size());
    digest.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte*)&digest[0]);
    CryptoPP::StringSource(digest, true, new CryptoPP::Redirector(encoder));
    hex_digest += 'h';

    CryptoPP::Integer m(hex_digest.c_str());
    CryptoPP::Integer ch_digest;
    CryptoPP::Integer tmp_1 = a_exp_b_mod_c(pk.g, m, pk.p);
    CryptoPP::Integer tmp_2 = a_exp_b_mod_c(pk.y, r, pk.p);
    ch_digest = a_times_b_mod_c(tmp_1, tmp_2, pk.p);

    return ch_digest;
}

// CH=g^m*h^r =g^m'*h^r' mod p，可得m+rx=m'+r'x mod q，继而可计算出r'=(m-m'+rx)*x^(-1) mod q
CryptoPP::Integer forge(std::string ori_msg, std::string new_msg, CHPublicKey pk, CHSecretKey sk, CryptoPP::Integer r){
    CryptoPP::Integer new_r;

    std::string hex_digest_ori;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hex_digest_ori));

    std::string hex_digest_new;
    CryptoPP::HexEncoder encoder_new(new CryptoPP::StringSink(hex_digest_new));

    std::string ori_digest;
    CryptoPP::SHA3_256 ori_hash;
    ori_hash.Update((const CryptoPP::byte*)ori_msg.data(), ori_msg.size());
    ori_digest.resize(ori_hash.DigestSize());
    ori_hash.Final((CryptoPP::byte*)&ori_digest[0]);
    CryptoPP::StringSource(ori_digest, true, new CryptoPP::Redirector(encoder));

    std::string new_digest;
    CryptoPP::SHA3_256 new_hash;
    new_hash.Update((const CryptoPP::byte*)new_msg.data(), new_msg.size());
    new_digest.resize(new_hash.DigestSize());
    new_hash.Final((CryptoPP::byte*)&new_digest[0]);
    CryptoPP::StringSource(new_digest, true, new CryptoPP::Redirector(encoder_new));

    hex_digest_ori += 'h';
    hex_digest_new += 'h';

    CryptoPP::Integer m(hex_digest_ori.c_str());
    CryptoPP::Integer new_m(hex_digest_new.c_str());


    CryptoPP::Integer diff = m - new_m;
    CryptoPP::Integer inverse = sk.sk.InverseMod(pk.q);
    CryptoPP::Integer tmp = diff * inverse;
    new_r = (tmp + r) % pk.q;

    return new_r;
}

int main(int argc, const char* argv[]){
    auto [pk, sk] = Keygen(1, 1024);
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::Integer r(prng, 0, pk.q);

    std::string s = "5465465465";
    clock_t start = clock();
    CryptoPP::Integer ch = chameleonHash(s, pk, sk, r);
    clock_t finish = clock();
    std::cout << "chameleon hash: " << ch << std::endl;
    double Times = (double)(finish - start) / CLOCKS_PER_SEC;
    std::cout << "Generation time: " << Times << "s." << std::endl;

    std::string new_s = "1asfasfsafasfas";
    clock_t forge_start = clock();
    CryptoPP::Integer new_r = forge(s, new_s, pk, sk, r);
    clock_t forge_finish = clock();
    std::cout << "r_1: " << r << std::endl;
    std::cout << "r_2: " << new_r << std::endl;
    double forge_Times = (double)(forge_finish - forge_start) / CLOCKS_PER_SEC;
    std::cout << "Forge time: " << forge_Times << "s." << std::endl;

    auto re1 = chameleonHash(s, pk, sk, r);
    auto re2 = chameleonHash(new_s, pk, sk, new_r);
    std::cout << "Original_hash: " << re1 << std::endl;
    std::cout << "Now_hash: " << re2 << std::endl;

    if(re1 == re2){
        std::cout << "The hash is same." << std::endl;
    }

    return 0;
}

