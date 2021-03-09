#include "abe.h"


class BooleanCircuit : public CP_ABE::BaseAccessStructure {
public:
	int node_count;
	vector <vector <int>> in_edges, out_edges;
	vector <int> gates, f;
	vector <CP_ABE::Attribute> attributes;
	vector <vector<Zr>> shares;

	BooleanCircuit(int node_count) {
		this->node_count = node_count;
		shares = vector <vector <Zr>> (node_count, vector <Zr>() );
	}

	map <CP_ABE::Attribute, vector <Zr>> share(Zr secret);
	void dfs(int node, Zr secret);
	std::pair<bool, GT> dfs2(int node, const map <CP_ABE::Attribute, vector <GT> >& v);
	std::pair<bool, GT> recon(map <CP_ABE::Attribute, vector <GT>>);
};
