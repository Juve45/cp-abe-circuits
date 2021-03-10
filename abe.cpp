#include "abe.h"

namespace CP_ABE {


  // GT int_to_GT(int value) {

  // }

  // int GT_to_int(GT value) {
  //   mpz_t extra, msg;

  //   mpz_init(extra);
  //   mpz_init(msg_gt);
    
  //   element_to_mpz(msg_gt, message_GT);
  //   mpz_sub(ciphertext->extra, message , msg_gt);
  // }

  G1 Attribute::hash(Pairing * pairing) {
    string str = this->get_str_value();
    return G1 (*pairing, str.c_str(), str.size());
  }

  void get_mpz(mpz_t big_integer, GT gt) {
    // mpz_t big_integer;
    mpz_init(big_integer);
    mpz_set_si(big_integer, 100);
    element_to_mpz(big_integer, gt.getElement());
    return big_integer;
  }


  std::pair<PublicKey, MasterKey> Controller::setup(const Pairing &pairing) {

    PublicKey public_key = PublicKey();
    MasterKey master_key = MasterKey();

    Zr alpha(pairing, true);

    
    public_key.pairing    = (Pairing*) &pairing;
    public_key.g          = G1(pairing, false);
    public_key.egg_alpha  = pairing(public_key.g, public_key.g)^alpha;

    master_key.beta       = Zr(pairing, true);
    master_key.g_alpha    = public_key.g ^ alpha;
    public_key.alpha      = alpha;
    
    public_key.h          = public_key.g ^ master_key.beta;

    pair<PublicKey, MasterKey> ret;
    ret.first = public_key;
    ret.second = master_key;

    return ret;
  }

  
  DecryptionKey Controller::keygen(const PublicKey public_key, 
                                    const MasterKey master_key, 
                                    std::vector <Attribute> attributes) {
      
    DecryptionKey decryption_key;
    map<Attribute, Zr> r_j;
    Zr r = Zr(*public_key.pairing, true);
    decryption_key.r =r;

    for(auto a : attributes) {
      r_j[a] = Zr(*public_key.pairing, true);
    }
    

    decryption_key.d = master_key.g_alpha ^ master_key.beta.inverse();
    G1 gg = (public_key.g ^ (r * master_key.beta.inverse()));
    decryption_key.d *= gg;

    for(auto a : attributes) {
      decryption_key.d_j[a] = (public_key.g ^ r) * (a.hash(public_key.pairing) ^ r_j[a]);
      //CP_ABE::get_attr_hash(*public_key.pairing, attribute)
      decryption_key.d_j_p[a] = public_key.g ^ r_j[a];
    }

    return decryption_key;

  }


  Ciphertext Controller::encrypt(mpz_t message, const PublicKey& public_key, 
                                 BaseAccessStructure* access_structure) {

    Ciphertext ciphertext;
    access_structure->pairing = public_key.pairing;
    
    ciphertext.access_structure = access_structure;
    Zr s = Zr(*public_key.pairing, true);
    
    ciphertext.s = s; // delete this
    
    map <Attribute, vector <Zr> >  attr_shares = access_structure->share(s);


    for(auto & [attribute, shares] : attr_shares)
      for(const auto &i : shares) {
        ciphertext.c_x[attribute].push_back(public_key.g ^ i);
        ciphertext.c_x_prim[attribute].push_back(attribute.hash(public_key.pairing) ^ i);  
        //CP_ABE::get_attr_hash(*public_key.pairing, attribute)
      }
    ciphertext.c    = public_key.h ^ s;
    ciphertext.c_m  = public_key.egg_alpha ^ s;
    GT m_t          = GT(*public_key.pairing, false);
    // m_t.dump(stdout, "message in GT: ");
    get_mpz(ciphertext.extra , m_t);
    
    mpz_out_str(stdout, 10, ciphertext.extra);
    cout << endl;
    mpz_sub(ciphertext.extra, ciphertext.extra, message);
    
    mpz_out_str(stdout, 10, ciphertext.extra);
    cout << endl;

    ciphertext.c_m *= m_t;

    return ciphertext;
  }

  void Controller::decrypt(const Ciphertext& ciphertext, 
                          const DecryptionKey& decryption_key,
                          const PublicKey& public_key) {
    map <Attribute, vector<GT>> v;

    for( auto [attribute, d_attr] : decryption_key.d_j) {
      cout << "attr: " << attribute.value << ", " << ciphertext.c_x[attribute].size() << endl;
      for(int i = 0; i < ciphertext.c_x[attribute].size(); i++) {
        cout << i << ' ' << endl;
        G1 d_prim = decryption_key.d_j_p[attribute];
        G1 c_x_prim = ciphertext.c_x_prim[attribute][i];
        GT tmp = (*public_key.pairing)(d_attr, ciphertext.c_x[attribute][i]) / 
          (*public_key.pairing)(d_prim, c_x_prim);
        v[attribute].push_back(tmp);
      }
    }
    cout << "OK" << endl;

    auto res = ciphertext.access_structure->recon(v);
    cout << "OK" << endl;
    if(res.first == false) 
      return -1; // access structure not satisfied
    GT egg_rs = res.second;

    egg_rs.dump(stdout, "e(g,g)^rs");

    GT m = ciphertext.c_m * egg_rs / (*public_key.pairing)(ciphertext.c, decryption_key.d);

    // ciphertext.extra = get_mpz(m_t);



    mpz_t message;
    mpz_init(message);
    get_mpz(message, m);


    mpz_sub(message, message, ciphertext.extra);

    cout << "recovered message is: "; 
    mpz_out_str(stdout, 10, message);
    cout << endl;


    // m.dump(stdout, "Recovered message in GT is: ");
    // element_printf("%Z\n", ms);

    // mpz_t z;
  }



}

