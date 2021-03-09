#ifndef __CP_ABE_H__
#define __CP_ABE_H__


#include "PBC.h"
#include <vector>
#include <map>

namespace CP_ABE {

	class Attribute {

		string attribute;
	public:
		int value;
		Attribute(int value) {this->value=value;}

		bool operator<(const Attribute& rhs) const { return value < rhs.value; };
	};

	class BaseAccessStructure {
	public:
		virtual map <Attribute, vector <Zr>> share(Zr secret);
  		virtual std::pair<bool, GT> recon(map <Attribute, vector <GT>> v);
	};

	struct Ciphertext {
		BaseAccessStructure access_structure; 
		GT c_m;
		G1 c;
		Zr s;
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
		Zr alpha;
	};

	struct DecryptionKey {
		G1 d;
		Zr r;
		map <Attribute, G1> d_j, d_j_p;
	};

	class Controller {
	public:
		std::pair<PublicKey, MasterKey> setup(const Pairing &pairing);

		Ciphertext encrypt(int message, const PublicKey& publicKey, BooleanCircuit& boolean_circuit);

		DecryptionKey* keygen(const PublicKey public_key, const MasterKey master_key, std::vector <Attribute> attributes);
		
		int decrypt(const Ciphertext& ciphertext, const DecryptionKey& decryption_key, const PublicKey& public_key);
		
	private:


	};

	// G1 get_attr_hash(const Pairing& pairing, Attribute a) {
	// 	return G1(pairing, true);
	// }

}
#endif