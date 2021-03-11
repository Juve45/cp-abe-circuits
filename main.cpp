#include "abe.h"
#include "boolean_circuit.h"

int main(int argc, char * argv[]) {

	CP_ABE::Controller cp_abe = CP_ABE::Controller();

	const char *paramFileName = (argc > 1) ? argv[1] : "pairing.param";
	FILE *sysParamFile = fopen(paramFileName, "r");
	if (sysParamFile == NULL) {
		cerr<<"Can't open the parameter file " << paramFileName << "\n";
		cerr<<"Usage: " << argv[0] << " [paramfile]\n";
		return 0;
	}
	Pairing e(sysParamFile);

	auto p = cp_abe.setup(e);

	cout << "Is symmetric? " << e.isSymmetric() << endl;
	cout << "Is pairing present? " << e.isPairingPresent() << endl;  

	auto pk = p.first;
	auto msk = p.second;

	vector <CP_ABE::Attribute> a;
	a.push_back(CP_ABE::Attribute(1));
	a.push_back(CP_ABE::Attribute(4));
	a.push_back(CP_ABE::Attribute(15));

	auto dkey = cp_abe.keygen(pk, msk, a);

	// Boolean circuit with 5 nodes
	BooleanCircuit bc(5);
	bc.in_edges = {{1, 4}, {2, 3}, {}, {}, {}};
	bc.out_edges = {{}, {0}, {1}, {1}, {0}};
	bc.gates = {0, 1, 0, 0, 0};


	bc.attributes = {CP_ABE::Attribute(-1), CP_ABE::Attribute(-1), a[0], a[1], a[2]};

	CP_ABE::Ciphertext ct = cp_abe.encrypt(123, pk, &bc);

	cout << "Encrypted! " << endl;

	cout << "Recovered: " << cp_abe.decrypt(ct, dkey, pk);


}