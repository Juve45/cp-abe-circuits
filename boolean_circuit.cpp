#ifndef __BOOLEAN_CIRCUIT_H__
#define __BOOLEAN_CIRCUIT_H__

#include "boolean_circuit.h"


void BooleanCircuit::dfs(int node, Zr secret) {


  cout << node << ' ' << in_edges[node].size(); cout.flush();

  if(in_edges[node].size() == 0)  {
    shares[node].push_back(secret); 
    return;
  }
  shares[node] = { secret };
  cout << " T ";cout.flush();

  if(gates[node] == 0) { // OR gate

    for(auto i : in_edges[node]) {
      (cout << i).flush();
      dfs(i, secret);
    }
  } else { // AND gate
    cout << "At the AND" << pairing << endl;
    Zr sum = Zr(*pairing, (long int) 0);

    cout << "At the begining" << endl;
    for(int i = 1; i < in_edges[node].size(); i++) {
      Zr x = Zr(*pairing, true);
      sum += x;
      dfs(in_edges[node][i], x);
    }
    cout << "At the end" << endl;

    dfs(in_edges[node][0], secret - sum);
  }
}




map <CP_ABE::Attribute,  vector <Zr>> BooleanCircuit::share(Zr secret) {
  map <CP_ABE::Attribute, vector <Zr> > attr_shares;
  shares = vector<vector<Zr>>(node_count, vector <Zr>());

  dfs(0, secret);

  for(int i = 0; i < attributes.size(); i++) {
    if(attributes[i].value == -1) 
      continue;
    
    attr_shares[attributes[i]] = shares[i];
  }
  shares.clear();
  return attr_shares;
}

std::pair<bool, GT> BooleanCircuit::dfs2(int node, 
  const map <CP_ABE::Attribute, vector <GT>> &v) {
  
  cout << "node " << node << endl;

  if(in_edges[node].size() == 0) {
    cout << v.count(attributes[node]) << f[node] << endl;
    if(v.count(attributes[node]) > 0) 
      return {true, v[attributes[node]][ f[node]++ ]};
    else return {false, GT(*pairing, true)};
  }

  vector <pair<bool, GT> > shares;  
  for(int i = 0; i < in_edges[node].size(); i++) 
    shares.push_back(dfs2(in_edges[node][i], v));
  
  if(gates[node] == 0) {
    for(auto i : shares)
      if(i.first)
        return i;
  } else {
    GT ret = GT(*pairing, true);
    for(auto i : shares) 
      if(i.first == 0)
        return i;
      else ret *= i.second;
      return {true, ret};
  }
  return {false, GT()};

}

std::pair<bool, GT> BooleanCircuit::recon(map <CP_ABE::Attribute, vector <GT>> v) {
  f = vector <int> (node_count, 0);
  return dfs2(0, v);
}

#endif