# Capstone-Project-ESA-Lightweight-Cryptographic-Algorithms-for-Securing-IoT-Healthcare-Data

Project ID: PW21VB02
Project Title: Lightweight Cryptography Algorithms for securing IoT-Health Care Data.

Team Members: V Nayana (PES1201701580),
 Prathusha K (PES1201701831),
 Manasa H K (PES1201701886),
 Aishwarya M M (PES1201802368)
              
Project Guide: Assistant Prof. Vineetha B 

Steps for Execution:

PRESENT
1. Run "present.c".
2. Enter a 64-bit plaintext in hexadecimal format.
3. Enter a 80-bit key in hexadecimal format.
4. Encryption of the plaintext into cipher text is performed.
5. Decryption of the same encipher is performed to obtain the original plaintext.
	
ASCON
1. Run ascon.py.
2. We send a key, nonce, associated data, plaintext and variant as input.
3. Data of plaintext is processed which takes ascon state, intermediate rounds, which returns the cipher text.
4. For decryption a similar process like present is carried out, but it uses inverse permutation table and inverse s-box to get back the plain text.  
