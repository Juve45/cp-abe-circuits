#include <pbc.h>

class Pairing {
	pairing_t pairing;
	
	Pairing()

	GroupT e(Group1 e1, Group2 e2);
	Group1 getE1();
	Group2 getE2();

	pairing_init_pbc_param(pairing, param);
}




class G1 : G {

}

class G2 : G {

}


class GT {


}


pairing_pp_t pp;
pairing_pp_init(pp, x, pairing); // x is some element of G1
pairing_pp_apply(r1, y1, pp); // r1 = e(x, y1)
pairing_pp_apply(r2, y2, pp); // r2 = e(x, y2)
pairing_pp_clear(pp); // don't need pp anymore
