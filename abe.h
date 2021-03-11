#ifndef __CP_ABE_H__
#define __CP_ABE_H__


#include "pbc/PBC.h"
#include <vector>
#include <map>

namespace CP_ABE {


	class Attribute {

	public:
		string name;
		int value;
		bool isNumeric;
		Attribute(int value) {this->value=value; isNumeric = true;}
		Attribute(string name) {this->name=name; isNumeric = false;}

		bool operator<(const Attribute& rhs) const { return value < rhs.value; };
		string get_str_value() {
			if(isNumeric)
				return to_string(value);
			return name;
		}

		G1 hash(Pairing * pairing);
	};


	class BaseAccessStructure {
	public:
		Pairing *pairing;
		virtual map <Attribute, vector <Zr>> share(Zr secret) = 0;
  		virtual std::pair<bool, GT> recon(map <Attribute, vector <GT>> v) = 0;
	};

	struct Ciphertext {
		BaseAccessStructure *access_structure; 
		GT c_m;
		G1 c;
		mpz_t extra;
		map <Attribute, vector <G1>> c_x, c_x_prim;
	};

	struct MasterKey {
		Zr beta;
		G1 g_alpha;
	};

	struct PublicKey {
		Pairing *pairing;
		G1 g;
		G1 h;
		GT egg_alpha;
	};

	struct DecryptionKey {
		G1 d;
		Zr r;
		map <Attribute, G1> d_j, d_j_p;
	};

	class Controller {
	public:
		std::pair<PublicKey, MasterKey> setup(const Pairing &pairing);

		Ciphertext encrypt(int message, const PublicKey& publicKey, BaseAccessStructure* boolean_circuit);

		DecryptionKey keygen(const PublicKey public_key, const MasterKey master_key, std::vector <Attribute> attributes);
		
		int decrypt(const Ciphertext& ciphertext, const DecryptionKey& decryption_key, const PublicKey& public_key);
		
	private:


	};

	// G1 get_attr_hash(const Pairing& pairing, Attribute a) {
	// 	return G1(pairing, true);
	// }

}
#endif