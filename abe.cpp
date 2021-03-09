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
      decryption_key.d_j[a] = (public_key.g ^ r) * (public_key.g ^ r_j[a]);
      //CP_ABE::get_attr_hash(*public_key.pairing, attribute)
      decryption_key.d_j_p[a] = public_key.g ^ r_j[a];
    }

    return decryption_key;

  }


  Ciphertext Controller::encrypt(int message, const PublicKey& public_key, 
                                 BaseAccessStructure* access_structure) {

    Ciphertext ciphertext;
    access_structure->pairing = public_key.pairing;
    cout << "Pairing: " << access_structure->pairing << endl;
    ciphertext.access_structure = access_structure;
    Zr s = Zr(*public_key.pairing, true);
    
    ciphertext.s = s; // delete this
    cout << "Here" << endl;
    map <Attribute, vector <Zr> >  attr_shares = access_structure->share(s);


    for(auto & [attribute, shares] : attr_shares)
      for(const auto &i : shares) {
        ciphertext.c_x[attribute].push_back(public_key.g ^ i);
        ciphertext.c_x_prim[attribute].push_back(public_key.g ^ i);  
        //CP_ABE::get_attr_hash(*public_key.pairing, attribute)
      }
    ciphertext.c    = public_key.h ^ s;
    ciphertext.c_m  = public_key.egg_alpha ^ s;
    GT m_t          = GT(*public_key.pairing, false);
    m_t.dump(stdout, "message (rand) in GT:");
    element_t element;
    element_init_same_as(element, m_t.getElement());

    mpz_t z;
    mpz_init(z);
    mpz_set_si(z,123);
    element_random(element);

    m_t.setElement(element);


    element_to_mpz(z, element);
    gmp_printf ("%s is an mpz %Zd\n", "here", z);
    element_to_mpz(z, m_t.getElement());
    gmp_printf ("%s is an mpz %Zd\n", "here", z);

    m_t.dump(stdout, "message (norm) in GT:");
    ciphertext.c_m *= m_t;

    return ciphertext;
  }

  int Controller::decrypt(const Ciphertext& ciphertext, 
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
    GT gre = (*public_key.pairing)(public_key.g, public_key.g) ^ (ciphertext.s * decryption_key.r);

    gre.dump(stdout, "gre:");
    egg_rs.dump(stdout, "e(g,g)^rs");

    GT m = ciphertext.c_m * egg_rs / (*public_key.pairing)(ciphertext.c, decryption_key.d);

    ((*public_key.pairing)(ciphertext.c, decryption_key.d)).dump(stdout, "e(g, g)^(alpha+r)s - ");
    ((*public_key.pairing)(public_key.g, public_key.g)^(ciphertext.s * (decryption_key.r + public_key.alpha))).dump(stdout, "e(g, g)^(alpha+r)s - ");



    m.dump(stdout, "Recovered message in GT is: ");
    // element_printf("%Z\n", ms);

    return 0;
    // mpz_t z;
  }



}

