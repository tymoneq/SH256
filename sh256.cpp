#include <bits/stdc++.h>

using namespace std;

typedef unsigned int uint;
typedef unsigned long long ull;

class SHA256
{
protected:
    char Hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    uint H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    string password = "";

    vector<uint> binary_password;
    int password_length = 0;
    const int binary_word_length = 32;
    const ull BigEndian = (ull)1 << 32;

public:
    SHA256(string _passowrd)
    {
        this->password = _passowrd;
    }

    inline void transform_to_binary()
    {

        for (int indx = 0; indx < password.size(); indx += 4)
        {
            uint binary_word = 0;

            for (int j = 0; j < 4 && indx + j < password.size(); j++)
            {
                password_length += 8;
                uint character = password[j + indx];

                binary_word += (character << (8 * j));
            }

            binary_password.push_back(binary_word);
        }
    }

    inline void pre_procesing()
    {

        // add 1 then add 0

        if (password_length % binary_word_length == 0)
        {
            binary_password.push_back(1);
            password_length += binary_word_length;
        }
        else
        {
            int mod = password_length % binary_word_length;
            binary_password[binary_password.size() - 1] += (1 << mod);

            password_length -= mod;
            password_length += binary_word_length;
        }

        while (password_length % 512 != 480)
        {
            password_length += binary_word_length;
            binary_password.push_back(0);
        }
        // add length of a passowrd

        ull binary_pass_length = password.size();

        while ((binary_pass_length << 1) < BigEndian)
            binary_pass_length = (binary_pass_length << 1);

        binary_password.push_back(binary_pass_length);
        password_length += 32;
    }

    inline uint rotr(uint value, uint shift)
    {
        return (value >> shift) | (value << (binary_word_length - shift));
    }

    inline uint sigma0(uint bin_number)
    {
        uint num1 = rotr(bin_number, 7);
        uint num2 = rotr(bin_number, 18);
        uint num3 = bin_number >> 3;

        ull res = num1 + num2 + num3;

        res %= BigEndian;

        res = (uint)res;

        return res;
    }

    inline uint sigma1(uint bin_number)
    {
        uint num1 = rotr(bin_number, 17);
        uint num2 = rotr(bin_number, 19);
        uint num3 = bin_number >> 10;

        ull res = num1 + num2 + num3;

        res %= BigEndian;

        res = (uint)res;

        return res;
    }

    inline uint BigSigma0(uint bin_number)
    {
        uint num1 = rotr(bin_number, 2);
        uint num2 = rotr(bin_number, 13);
        uint num3 = rotr(bin_number, 22);

        ull res = num1 + num2 + num3;

        res %= BigEndian;
        return uint(res);
    }

    inline uint BigSigma1(uint bin_number)
    {
        uint num1 = rotr(bin_number, 6);
        uint num2 = rotr(bin_number, 11);
        uint num3 = rotr(bin_number, 25);

        ull res = num1 + num2 + num3;

        res %= BigEndian;
        return uint(res);
    }

    inline uint ch(uint e, uint f, uint g)
    {
        uint ans = 0;

        for (int bit = 0; bit < binary_word_length; bit++)
        {
            // take f
            if (e & (1 << bit))
                ans += ((f & (1 << bit)) << bit);

            // take g
            else
                ans += ((g & (1 << bit)) << bit);
        }

        return ans;
    }

    inline void check_bit(const uint &num, const int &bit, int &cnt0, int &cnt1)
    {
        if (num & (1 << bit))
            cnt1++;
        else
            cnt0++;
    }
    inline uint Maj(uint a, uint b, uint c)
    {
        uint ans = 0;
        for (int bit = 0; bit < binary_word_length; bit++)
        {
            int cnt0 = 0;
            int cnt1 = 0;

            check_bit(a, bit, cnt0, cnt1);
            check_bit(b, bit, cnt0, cnt1);
            check_bit(c, bit, cnt0, cnt1);

            if (cnt1 > cnt0)
                ans += (1 << bit);
        }

        return ans;
    }

    inline void computation()
    {
        for (int i = 0; i * 512 < password_length; i++)
        {
            int start = 16 * i;
            vector<uint> W(64);

            for (int j = 0; j < 16; j++)
                W[j] = binary_password[j + start];

            for (int t = 16; t < 64; t++)
                W[t] = ((ull)sigma1(W[t - 2]) + (ull)W[t - 7] + (ull)sigma0(W[t - 15]) + (ull)W[t - 16]) % BigEndian;

            uint a = H[0];
            uint b = H[1];
            uint c = H[2];
            uint d = H[3];
            uint e = H[4];
            uint f = H[5];
            uint g = H[6];
            uint h = H[7];

            for (int j = 0; j < 64; j++)
            {
                uint T1 = ((ull)h + (ull)BigSigma1(e) + (ull)ch(e, f, g) + (ull)K[j] + (ull)W[j]) % BigEndian;
                uint T2 = ((ull)BigSigma0(a) + (ull)Maj(a, b, c)) % BigEndian;

                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }

            H[0] = ((ull)H[0] + (ull)a) % BigEndian;
            H[1] = ((ull)H[1] + (ull)b) % BigEndian;
            H[2] = ((ull)H[2] + (ull)c) % BigEndian;
            H[3] = ((ull)H[3] + (ull)d) % BigEndian;
            H[4] = ((ull)H[4] + (ull)e) % BigEndian;
            H[5] = ((ull)H[5] + (ull)f) % BigEndian;
            H[6] = ((ull)H[6] + (ull)g) % BigEndian;
            H[7] = ((ull)H[7] + (ull)h) % BigEndian;
        }
    }

    inline string get_hash()
    {
        string hash = "";

        for (int i = 0; i < 8; i++)
            for (int j = 0; j < 8; j++)
            {
                uint num = 0;

                for (int bit = 0; bit < 4; bit++)
                    if (H[i] & (1 << (bit + (4 * j))))
                        num += (1 << bit);

                hash += Hex[num];
            }

        return hash;
    }
    inline string encypt()
    {
        transform_to_binary();
        pre_procesing();
        computation();
        string hash = get_hash();

        return hash;
    }
};

int main()
{

    string password;

    cout << "ENTER PASSWORD:\n";
    cin >> password;

    SHA256 hasher(password);
    string hash = hasher.encypt();

    cout << "YOUR HASH:\n";
    cout << hash << '\n';
    return 0;
}