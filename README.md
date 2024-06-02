# RSA-algorithm
Project Overview
This project focuses on implementing digital signatures using the Merkle-Damgård (MD) hash function and the RSA algorithm. Here's a brief overview of the key concepts:

Merkle-Damgård Hash Function: Converts large input files into fixed-size hash values, ensuring efficient handling by the RSA algorithm.

RSA Algorithm: Generates secure cryptographic keys and performs encryption and decryption operations. It ensures secure communication by creating digital signatures.

Integration in the Application
The Signature application uses MD4 for hashing and RSA for digital signatures.

MD4 Hash Function: Processes input messages to produce fixed-size hashes.

RSA Algorithm: Generates digital signatures for the hashes using private keys. These signatures can be verified using corresponding public keys to ensure message authenticity and integrity.

Requirements
Basic understanding of computer science concepts such as bits, bitwise operations, and little-endian format.

Familiarity with abstract algebra, particularly properties of fields 
Zp and rings Zpq.



This README provides a concise overview of the project, explaining its purpose, key components, and usage instructions.
