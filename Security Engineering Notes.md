How many bits is secure?
Birthday attack
Zero knowledge proof examples
RSA



# Reading list
1. Kevin Mitnik - The art of Deception
2. The Art of intrusion
3. Smashing the stack for fun and profit : http://insecure.org/stf/smashstack.html
4. Applied Cryptography Protocols, Algorithms, and Source Code in C, Bruce Schneier


Great summary : https://www.cs.rutgers.edu/~pxk/rutgers/notes/content/13-crypto.pdf
Good resource : http://www.quadibloc.com/crypto/hjscrypt.htm
ell

# Potential exam questions
## Stargate problem

## Zero Knowledge Proofs

## Training - firearms manual
### Older
* Most of the content was safety
* Explained the reasons behind the safety, not just the rules
* Had pictures
h

##Bits of security

## Interlock Protocol



## Ten problems with PKI
1. PKI tells you the certificate is valid, not whether or not you should TRUST it for what you intend to use it for
2. Someone else might use your private key and pretend to be you. All computers can be hacked.
3. How secure is the verifying computer? Can't someone just add a public key to your approved root certificates?
4. PKI just proves you are AN ADAM. They don't prove you are the Adam you want to speak to. 
5. CAs decide whether people can use SSL or SSH but what makes them an authority in that?
6. Users are expected to do some verifying - that the cert matches what the website is purporting to be. A system that relies on this is certain to fail. 
7. Separating certificate authorities and registration authorities means you are creating an organisation that has the ability to issue certs that wouldn't have to do the ground work if they didn't want to. This is another chain that could be weak, despite how above board the CA is.
8. Some CAs verify people's data with publicly available data from credit agencies. That doesn't really make sense. 
9. Are the certificates being used properly?
10.  



# Basics
## Kerckhoffs Principle

A cryptosystem should be secure even if everything about it, except the key, is public knowledge

1. A cipher should be unbreakable. If it cannot be theoretically proven to be unbreakable, it should at least be unbreakable in practice.
1. If the method of encipherment becomes known to one's adversary, this should not prevent one from continuing to use the cipher.
1. It should be possible to memorise the key without having to write it down, and it should be easy to change to a different key.
1. Messages, after being enciphered, should be in a form that can be sent by telegraph.
1. If a cipher machine or code book or the like is involved, any such items required should be portal

## Properties of Security Protocols
* **Confidentiality**
* **Integrity**
* **Authentication** 
* **Availability** 
* **Non-repudiation** 

## Weaknesses of systems
* **Abuse of trust** - Trust is the source of most security vulnerabilities. 
* **Weakest link** - Security is only as strong as the weakest link. Often this will be the human element. 
* **Out of Spec** - Most testing doesn't test things that aren't planned for. 
* **Asymmetry** - It is much harder to defend than to attack. 
* **In-band control signals** - When the data and control signals are in the same band (think SQL injection attacks). 


## Properties of a good system
* Practically, if not mathematically, indecipherable
* Does not depend upon secrecy or obscurity
* Easy to use
* Defence in depth - multiple layers
* Graceful failures


## Commitment
A commitment scheme allows one to commit to a chosen value (or chosen statement) while keeping it hidden to others, with the ability to reveal the committed value later. 

Commitment schemes are typically used in Zero Knowledge proofs. 

## Arbiterless Arbitration
A protocol of decision making which is fair/trusted by all parties but does not need an external third party to run the procedure. Think PGP vs PKI. 




# Glossary
* **Zero day exploits** - A weakness in software unknown by the vendor at the time of release, which can be first exploited by hackers. 0DX are extremely valuable, so are often saved for important hacks or even sold. 
* **Cryptographic primitives** - Well established low level crypto algorithms that are the building blocks for crypto protocols. ie. hashes, ciphers, tokenisation, random number generators, steganography. 
* **Type I/Type II Errors** - 
* **Reconnaissance** - Active and Passive - Active engages with the system to be targeted, in a way that may trigger warning systems (sending packets, scanning for open ports). Passive is methods that can't be traced or don't appear suspicious. (Whois lookup, visiting websites, reading pamphlets). 
* **Dumpster diving**
* **Chinese wall** - To make sure that one of your own group of people don’t share information with another of your groups of people, for example, where information sharing is illegal. e.g. if a firm has a department of stock trading they shouldn’t know what your mergers and acquisitions people know.
* **Mandatory Access Control** - Where you have rules which are mandatorily enforced. Used in organisations (like the military) where there is no trust. 
* **Dual control** - Like in war games, requires two people to authorise something to happen. 
* **Principle of least privilege** - Only give people the power they need, not the power they want
* **White listing** - A register of entities that are being provided a particular privilege, access or recognition. 


# Training people
## Why bother?
* Humans are always the weakness in the systems
* Humans are not reliable!
* Humans are also our biggest potential threats

## How to train better
* Spread it out
* You need to understand the system/users first before designing the training. 
* Make it 
	* practical
	* Effective and fun
	* Realistic
	* Keep it simple
	* Easy to understand
	* Easy to follow
	* Fit with the kind of people who you want to follow the process
* Explain the reasoning behind it
* Make it enjoyable
* Make it engaging
* Gamify it
* Role playing
* Keep on updating it regularly


# Zero Knowledge Proof
https://mathoverflow.net/questions/22624/example-of-a-good-zero-knowledge-proof
https://www.cs.princeton.edu/courses/archive/fall07/cos433/lec15.pdf


# Crypto Primitives


## Hashes
Hashing maps a whole big number down to a smaller one. There are hash collisions, but we want the mapping to be spread as evenly as possible. 
**Cryptographic hashes**
These are different from traditional computing hashes as they need the following properties.

1. Quick to compute
2. One way function - Not possible to reverse without brute forcing
2. Cascading effect - a small change will result in half the bits changing
3. Not feasible to find two messages that hash to the same value


**Pre-image resistance** : Given the small thing it's hard to find the big thing. Hard to reverse. 

**Second pre-image resistance** : Given the big thing, its hard to find another big thing that creates the same small thing. 

**Collision resistance** : It should be difficult to find two messages that hash to the same value. 

### Vulnerabilities

**Length extension attack** - MD5 and SHA-1 are iterative hash functions. They break up the message into blocks of a fixed size and iterate over them with a compression function. 

**Birthday attack** - To find a collision in a hash, the birthday attack can be used. Based on the birthday paradox principles, the chances of finding any two messages that hash to the same value is a lot less than having to brute force all possibilities. Once a hash collision is detected this is extremely useful in uncovering how the algorithm generates that hash collision and can lead to exploits and the break down of the hash algorithm. Birthday attack on collisions takes about SQRT(items) on average. ie O(2n/2)
Read : https://www.hackthissite.org/articles/read/1066

### Examples of hashing algorithms

1. MD5
1. SHA1
1. SHA2 


## MACs
Stands for Message Authentication code. A short piece of info used to authenticate a message via the use of a secret key. Typically you want to encrypt a message, then MAC it to authenticate the encryption. 

HMAC provides **integrity** and **authentication**. 

### Vulnerabilities
#### **Length extension attack**
Hashing functions that use an iterative process (MD5, SHA1,2, NOT SHA3) are vulnerable to this kind of attack. 

* If **MAC = H(key ∥ message)** : It is easy to append data to the message without knowing the key and obtain another valid MAC 
* If **MAC = H(message ∥ key)** : If a hacker can find a collision in the hash function, they have a collision in the MAC, as the message before the key is appended will be the same, so the HMAC will be the same. 
* **H(key ∥  message | key))** : Is better but is also vulnerable. 
* **H(key ∥ H(key ∥ message))** : Current recommendation, as no extension attacks have been found currently. 

# Key Exchange
Good read DH vs RSA : https://security.stackexchange.com/questions/35471/is-there-any-particular-reason-to-use-diffie-hellman-over-rsa-for-key-exchange

## HTTPS
HTTPS is HTTP over SSL.
 

### TLS
Uses MACS, PKI, DHE! Has the following properties:
 
* **Confidential**, due to symmetric cryptography. Keys are negotiated at the beginning of the session with TLS handshake protocol. 
* **Authentication** - The identity of each party can be verified using **PKI**. Typically only the server is authenticated. 
* **PFS with a session key** - If an ephemeral key is negotiated then it can allow for Perfect Forward Secrecy
* **Integrity** - Message is reliable because of use of a **MAC** to prevent alteration during transmission. 

read : https://en.wikipedia.org/wiki/Transport_Layer_Security
https://security.stackexchange.com/questions/20803/how-does-ssl-tls-work


## Public Key Infrastructure (PKI)
A method used for signing and encrypting data with the aim of knowing who we are communicating with. It doesn't always achieve this! Requires asymmetric encryption and digital signatures. 

The goal of PKI is to provide users some verifiable guarantee as to the ownership of public keys. Public keys are authenticated via means of digital signatures.  

**Digital Certificates** - These are based off the X.509 certificates. Like a virtual ID card. The only reason a passport officer trusts your passport is because it was issued by the Australian government, which the USA government inherently trusts. Most computers inherently trust any certificates issued by third party certificate authorities such as VeriSign. 

Digital certificates contain

* An identity (e.g. server name)
* A public key (which supposedly belongs to that identity).

It is the role of the Certificate Authority to verify that the public key truely is that off the identity. If it is, then they sign the certificate with their own private key. Most browsers will inherently trust a top level certificate authority.

* **Example - Sending a signed email** - 
	1. Email message is hashed. 
	2. Hash is encrypted using private key and is appended to the end of the message. 
	3. Receiver can use public key to decrypt the hash, and can compare it against the email. 
	4. Provides authentication, and integrity. 

**N.B.** a signature itself does not make something trustworthy. If a message is signed, it says the message is as it was when the thing with the private key signed it. Now instead of having to trust the website we're going to (amazon) we have to trust the certificate authority. We have to trust that a CA won't knowingly or unknowingly sign a certificate with a wrong name/key association. 

Problems of PKI
* If one CA is compromised, the entire PKI is at risk

Good explanation : https://security.stackexchange.com/questions/87564/how-does-ssl-tls-pki-work
http://www.techrepublic.com/article/a-beginners-guide-to-public-key-infrastructure/
Extra reading : https://www.schneier.com/academic/paperfiles/paper-pki-ft.txt

## Web of trust
Used in PGP for emails.

As time goes on, yo accumulate keys from other people that you may want to designate as trusted introducers. Everyone else will each choose their own trusted introducers. And everyone will gradually accumulate and distribute with their key a collection of certifying signatures from other people, with the expectation that anyone receiving it will trust at least one or two of the signatures. This will cause the emergence of a decentralized fault-tolerant web of confidence for all public keys.


## Merkel Puzzles
1. Alice creates 1000 packets of ( unique message | unique key ). 
2. Bob randomly picks one of these, and spends the time brute forcing it. When done he uses the key to encrypt the message, and will send in plain text the unique message back to Alice.
3. Alice will lookup the key in her database using unique message as the identifier. 

https://www.youtube.com/watch?v=wRBkzEX-4Qo



## Diffie Hellman key exchange

1. One party publicly sends a g (generator - a prime number) and a n (mod value - also a prime number)
2. Alice comes up with private number A.
3. Bob comes up with a private number B. 
4. Alice computes (g^a mod n) and sends this to Bob.
5. Bob also computes (g^b mod n) and sends this to Alice. 
6. Alice takes Bob's message and raises it to her secret number. i.e. (g^b mod n)^a mod n. 
7. Bob takes Alice's message and raises it to his secret number i.e. g^a mod n)^ b mod n.
8. Alice and Bob have two value which are equal since : 
	9. (g^a mod p)^b mod p = g^ab mod p
	10. (gb mod p)^a mod p = g^ba mod p
	11. AND...  : g^ab mod p = g^ba mod p

	
	
	Alice: A = g^a mod n
			A = 2 ^5 mod 33
			A  = 32
			
			
			Malory: 
			M = g^m mod 33
			M = 2^10 mod 33
			M = 1
			
			
			B = g^b mod 33
			B = 2 ^ 


# Crypto

## Modern ciphers
### Stream cipher
Stream ciphers generate a stream of pseudo-random bits. This key stream is XORed with the plain text. These are based off trying to emulate one-time-pads. 

* The only real example is RC4, which is used in WEP and WPA. However there are vulnerabilities in RC4, so use has not been recommended. 

### Block cipher
A block cipher is an encryption algorithm that encrypts a fixed size of n-bits of data - known as a block - at one time. Majority of the symmetric ciphers used today are actually block ciphers. 

Block ciphers :

* **DES** Feistel - Data Encryption Standard. Formally known as Lucifer. Proven to be vulnerable to brute force attacks and cryptanalytic methods. 56 bit key. 
* **3DES** Feistel - DES that's run three times, usually with three different keys. Many times stronger than DES, but 3 times slower. 
* **AES** SP - Advanced Encryption Standard. It has a block size of 128 bits and supports three possible key sizes - 128, 192, and 256 bits. The longer the key size, the stronger the encryption. However, longer keys also result in longer processes of encryption.  
* **Blowfish** Feistel - This is another popular block cipher (although not as widely used as AES). It has a block size of 64 bits and supports a variable-length key that can range from 32 to 448 bits. One thing that makes blowfish so appealing is that Blowfish is unpatented and royalty-free. 

Block ciphers want the properties :
 
* **Confusion** - Each bit of cipher text should depend on several bits of the key.
* **Diffusion** - Changing one bit of the plain text should change half the bits of the cipher text on average. 

diffusion - dissipates statistical structure of plaintext over bulk of ciphertext
• confusion - makes relationship between ciphertext and key as complex as possible

Security of a block cipher depends on : 

* Choice of the cipher itself
* Choice of mode of operation
* Choice of padding scheme
* Choice of initialisation vector

#### Festal Network
A Feistel network uses a series of rounds that split the input block into two sides, uses one side to permute the other side, usually via XOR, then swaps the sides. Feistel is invertiable. 
![](https://upload.wikimedia.org/wikipedia/commons/f/fa/Feistel_cipher_diagram_en.svg)

### Substitution-Permutation Network
* **Substitution boxes** - Substitutes a small block of bits by another block of bits. Provides the **confusion** avalanche effect where changing one input bit will change half the output bits. 
* **Permutation box** - takes the outputs of all the s-Boxes of one round, permutes the bits and feeds them into the s-boxes of the next round. Provides the diffusion. 

![](https://upload.wikimedia.org/wikipedia/commons/thumb/c/cd/SubstitutionPermutationNetwork2.png/360px-SubstitutionPermutationNetwork2.png)

### Block Cipher Modes

**Electronic Codebook (ECB)**

The simplest of the encryption modes is the ECB mode. The message is divided into blocks, and each block is encrypted separately. The disadvantage of this method is that identical plaintext blocks are encrypted into identical ciphertext blocks; thus, it does not hide data patterns well. In some senses, it doesn't provide serious message confidentiality, and it is not recommended for use in cryptographic protocols at all.

**Cipher Block Chaining (CBC)**

In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted. This way, each ciphertext block depends on all plaintext blocks processed up to that point. To make each message unique, an initialization vector must be used in the first block. Its main drawbacks are that encryption is sequential (i.e., it cannot be parallelized), and that the message must be padded to a multiple of the cipher block size

**Counter (CTR)**

Counter mode turns a block cipher into a stream cipher. It generates the next keystream block by encrypting successive values of a "counter". The counter can be any function which produces a sequence which is guaranteed not to repeat for a long time


### Vulnerabilities
Padding oracle


## One time pads
1. Key needs to be as long as plain text
2. Plain text binary number is XORed with key binary number

* Proved by Claude Shannon to be perfect crypto if : 
	* Key is truely random
	* Key is as long as plain text
	* Never reused
	* Pad kept completely secret for ever

Flaws
* True randomness is hard
* If one of the keys is shared the whole situation is compromised. 
* Difficult to synchronise with partner
* Key distribution is difficult

## RSA Public Key Cryptography
https://www.cs.virginia.edu/~kam6zx/rsa/a-worked-example/

## Primitive Ciphers

### Steganography
Hiding information within another non-secret text or data
e.g. Writing secret messages directly on the wooden panel of a wax tablet, then covering it with the beeswax surface

### Substitution Cipher
Where single letters or groups of letters are swapped out with cipher text.

#### Monoalphabetic substitution cipher
**Mono alphabetic substitution cipher** - uses a fixed substitution over the entire message.
 
* **Simple substitution** - The alphabet in written out in some order next to the correct alphabet and this encoding is used. Can be broken by frequency analysis. 
	* **Caesar shift** - Ofsets the letters of the alphabet by 13
	* **Abash cipher** - Reverses the alphabet
 
**Polyalphabetic substitution cipher** - Uses a number of different substitutions at different positions in the message. 

* **Vigenère cipher** - The letters of a keyword are used to determine the offsets for a Caesar shift.  CAT is keyword. ABCDEFG is plaintext. CAT corresponds to +2,+0,+19. Cipher text is : CBVFE..... Broken via n-frequency analysis. 
* **Beaufort cipher** - Uses a keyword. Create an alphabetic grid, 26x26. As it goes down its offset by 1. Find the encode letter and find it's column. Run down the column until you hit the key letter. The letter that defines the row will be the cipher letter. 
* **Running key cipher** - Use a book to provide the offsets. This acts as a one-time pad.  
* **Playfair** - Write the keyword in a 5 by 5 grid. Then write the missing letters of the alphabet in the remaining boxes. Now use the first two letters of the cipher text to determine the first to letters of the cipher text (make a square with the two plain text letters, the other corners will be the cipher text). In the same column/row, each letter encrypts to the letter below/right of it. Use frequency analysis of bigrams to crack this. 
 

### Transposition cipher
The units of plain text are re-arranged in a different and complex order. However the original units are unchanged. 

* **Route cipher** - write in 5 x 5 grid, then read cipher text off in a pattern. i.e.  spiral inwards clockwise. 
* **Column transposition** - write in columns the length of a word. Then take the first alphabetical column's letters vertically as the first set of letters. Then the second letter column's letters. 
* **Rail Fence Cipher** - Write the words up and down in a triangular wave form, then read left to right. 


### Cracking ciphers
Most common letters in the English Alphabet : ETAOINSHRDLU. 



# Identity and Authentication
## Authentication multi-factors
* **Something you know** - passwords, security questions
* **Something you have** - mobile phone, swipe card
* **Something you are/do** - DNA, fingerprint

**N.B.**

* All of these essentially boil down to something you know, as these things are stored in a database based on facts. 
* A lot of biometrics is just security theatre.
* **Problem** : Once something you are gets compromised, it can't be changed. 

**Secrets**

* The problem with authentication via secrets is you have to divulge the secret frequently. 
	* We can take a hash
	* Challenge response

## Authentication vs Authorisation
* **Authorisation** - you are able to do certain things
* **Authentication** - you are who you say you are

## Authentication methods
1. Send secret, host can compare
2. Send secret, host stores hash of secret
3. Send secret, host stores hash with salt of secret
4. SKEY - one time use passwords. Host only stores previous password.
5. SKID - requires shared key, exchange encrypted hashes of randomly picked numbers, both ways. 
6. Using Public Key Exchange - Alice sends Pb(secret), and Bob returns with Pa(secret).

## SKEY
Logging in without revealing your password by using one-time passwords. SKEY requires a one-way function, f(), and a random number R. 

1. Generate a list of results 
	2. x1 = f(R)
	3. x2 = f(x1)
	4. x3 = f(x2)
	5. and so on. 
6. The computer stores the last result, x3, and the user keeps all x1-2. 
7. When Alice wants to log in, she gives x2, and we use it to compute x3. If it matches our stored value, we allow access, and store x2 as the new value in memory. 
8. Next time Alice logs in, she uses the next key on the list.


## SKID
Authentication scheme that uses symmetric crypto assuming a shared secret key between the two parties. SKID uses a keyed HMAC. 

* Alice chooses a random number Ra and sends to Bob
* Bob chooses a random number Rb. He computes a encrypted hash of (Ra, Rb, "Bob"), as well as sending Rb. 
* Alice can now also compute hash {Ra, Rb, "Bob"} and encrypts it with the key. By comparing the results, she can verify that Bob encrypted it. Alice is content she is speaking with the real Bob.
* SKID 3 continues on : Alices computes a hash of {Rb, "Alice"}, encrypts it, and sends it to Bob. 
* Bob computes the hash of {Rb, "Alice"} and compares it with the decryption of the value sent by Alice. Bob is now convinced of Alice's identity. 

The random number permeates the the data generated by the other. Each party is challenging the other with data which will be different each time authentication happens. 

## Interlock Protocol
Detects active man in the middle attacks where an attacker is re-encrypting messages on the fly. One method to ensure that we are not using Mallory's public key is to make sure the key comes with a certificate signed by a CA that we trust. 

**Interlock Protocol** - After both parties exchanged public keys, then each sent, in turn, the first half of an encrypted message, and then each sent, in turn, the second half of his or her own message.

1. Alice prepares a message encrypted with key 1 but only sends half of it. 
2. Mallory cannot decrypt it and re-encrypt it, so it forced to drop the packet, or pass it on
3. Bob receives half the message, so prepares an encrypted message with key 3, but only sends the first half. 
4. When Alice receives half the message, she sends the final half. 
5. Bob receives the second half of the message and is either able to decrypt the message, in which case it hasn't been tampered with, or the second half has been changed, in which case the message does not decrypt. 

More : http://www.quadibloc.com/crypto/mi060709.htm


## TOCTOU Errors
Time of check, time of use attack.

Examples : 

1. Linux check program has permission to write a file
	2. STOP IN BETWEEN – SETUP SYMBOLIC LINK TO A PASSWORD FILE! THE SYSTEM WILL THEN CHANGE THE PASSWORD FILE. YIPPIE!
	3. Then write file.
4. Movie theatre
5. Magic tricks - check first, it changes, then gets used


# Misc



## Software vulnerabilities
A bug in software that allows someone to use the system in a way that was unintended. The most common type of vulnerability is memory corruption. 

**Buffer overflow**

* Most common type of memory corruption attack
* A user inputs more than is allotted. This can overwrite important parts of the program. 
* Goal is to overwrite the return address using a buffer overflow attack
* The return address can be changed to wherever malicious code is and the computer can be made to run your malicious code. 


**Nop sleds**

* Because it can be difficult to land the program counter exactly to a place in memory, NOP sleds can be used as a landing zone before malicious code. 

**Shell code** 

* Popping a shell gives you terminal, which allows you to do a lot of things.

## Risk Management
1. **Prevention** - remove the bullets from a riffle to prevent it from firing.
2. **Limit** - Where threats can't be removed, they should be minimised. i.e. multiple walls around a castle
3. **Passing the risk** - Insurance, or making some one else responsible. 

## Threat Modelling
**Building a threat model**

Assets, potential attackers, threats, risks

1. Build a threat model
	2. Consider the assets
	3. Consider the risks,
	1. Consider the attackers
	1. Consider the attackers motives
2. List the threats
3. Deal with threats
	4. Stop it
	5. Minimise it
	6. Pass it on

**Common Sources of threats**

* Users
	* Unintentional attacks
	* Malicious attacks
* Attackers
	* Casual attacks - the victim is chosen incidentally
	* Determined attackers - targets the victim. Has motives against the victim. Tries to find vulnerabilities of the victim.
	* Funded attackers - CIA, Mossad. A determined attacker with much more resources. 
	* Insiders - May have more motivation, e.g. a disgruntled employee. Often have more knowledge of the system. 
* Natural disasters
* Movie plot level disasters
* Errors 

**Times of attack**
* A time of chaos
* When people are not ready for you
* When they're at their most vulnerable
* When tragedy occurs (floods, fires)
* When there is change (in management, bank key cards, mergers, takeovers, millennium bug)


## Social Engineering
1. Impersonating other people
2. Pre-texting - creating an artificial scenario around a target and pretending to be someone else.
3. Quid Pro quo - doing something for someone means they will be more open to doing something for you
4. Phishing - Asking people to fill in forms because of an issue
5. Spear-phishing - targeted phishing attack
6. Baiting - leaving free USBs lying in a car park
7. Tailgating - Following someone into a building. Holding a big box, being pregnant. 


## Moral Hazard
A moral hazard is when a situation is set up so that it incentivises people to act in a way that harms the system. 