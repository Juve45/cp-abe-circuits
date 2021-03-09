#include "abe.h"


class BooleanCircuit : public CP_ABE::BaseAccessStructure {
public:
	int node_count;
	vector <vector <int>> in_edges, out_edges;
	vector <int> gates, f;
	vector <CP_ABE::Attribute> attributes;
	vector <vector<Zr>> shares;
	Pairing *pairing;


		void dfs(int node, Zr secret);
		std::pair<bool, GT> dfs2(int node, const map <CP_ABE::Attribute, vector <GT> >& v);
		// map <Attribute, vector <Zr>> share(Zr secret);
		// std::pair<bool, GT> recon(map <Attribute, vector <GT>>);
};
