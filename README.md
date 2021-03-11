# cp-abe-circuits
Attribute Based Encryption for Boolean Circuits.

We provide implementation for an Ciphertext-policy Attribute-Based Encryption with Boolean circuits access structure
The implementation is written fully in C++, on top of the [PBC Library](https://crypto.stanford.edu/pbc/). 
It also uses the [C++ PBC Wrapper](https://crysp.uwaterloo.ca/software/PBCWrapper/).

## Installation

The SSBM requires PBC and GMP as requirements.
Also, we use the C++ PBCWrapper.
we included in our repository a pre-compiled version of the C++ PBC Wrapper (`libpbc.a`) along with the headers required (in `pbc/`)

## Compilation

Our algorithm can be compiled with the command:
```
g++ -static -std=c++17 main.cpp abe.cpp boolean_circuit.cpp libPBC.a -lpbc -lgmp -fpermissive -w
```


## CP_ABE Namespace

We have created a namespace that encapsulates our CP-ABE logic.
This namespace is called `CP-ABE` and it contains the following classes and structures :

* `Attribute` - This defines an CP-ABE Attribute. With an attribute you can associate an integer or a string.
* `PublicKey` - This datatype can keep a public key. 
* `MasterKey` - Stores the secret key.
* `DecryptionKey` - This structure holds decryption keys.
* `Ciphertext` - The result of the encryption algorithm
* `BaseAccessStructure` - This is an interface which defined how an access structure works (namely, `share` and `recon` function prototypes)
* `Controller` - This class encapsulated the maine functions of CP-ABE (`setup`, `encrypt`, `keygen`, `decrypt`)


## Setup
The setup algorithm sets the public and the secret parameters that are required later in the encryption, key generation and decryption phases.

```C++
CP_ABE::Controller cp_abe = CP_ABE::Controller();


PublicKey pk;
MasterKey msk;

//Receive a pair containing the public and master keys
pair<PublicKey, MasterKey> pp = cp_abe.setup();

pk = pp.first;
msk = pp.second;
```
 

## Encryption

The encryption algorithm encrypts an integer element, using the public key and an access structure.


Examples:
```C++

int message = 12345;

Ciphertext ct = cp_abe.encrypt(message, pk, access_structure);

```

`access_structure` is an element of type `BaseAccessStructure`. For more details, refer to the Access Structure section. 

## KeyGeneration
This algorithm recieves a compartmented acces structure, and returns the decryption keys corresponding to it.


```C++

vector <CP_ABE::Attribute> a;
a.push_back(CP_ABE::Attribute(1));
a.push_back(CP_ABE::Attribute(4));
a.push_back(CP_ABE::Attribute("Z"));

DecryptionKey dk = cp_abe.keygen(pk, msk, a);

```


## Decryption
The encryption algorithm encrypts an element from `mpz_t`.

Example: 
```C

int recovered_message = cp_abe.decrypt(ct, dkey, pk); 

```


## Access Structure

We provide an interface for access structures: `BaseAccessStructure`. In order to implement a valid access structure, only 2 algorithms are required: `share` and `recon`, which must
share and reconstruct the secret value from the access structure.

We provide an example of such implementation of a BooleanCircuit (`BooleanCircuit` in `boolean_circuit.h` and `boolean_circuit.cpp`).


Usage of our example `BooleanCuircut` class:

```
// Boolean circuit with 5 nodes
BooleanCircuit bc(5);
bc.in_edges = {{1, 4}, {2, 3}, {}, {}, {}};
bc.out_edges = {{}, {0}, {1}, {1}, {0}};
bc.gates = {0, 1, 0, 0, 0};
```



