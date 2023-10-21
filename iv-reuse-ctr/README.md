# IV reuse with AES-CTR
This project demonstrates a proof-of-concept of why reusing a nonce in AES-CTR (or any stream cipher really) is a bad idea.

# Disclaimer
Nothing in this repository should be used for production (especially the `encryptCTR` function) or nefarious purposes.

# Run
In Node.js, run `npm install && npm start`.

# Acknowledgments
I based the idea of this example out of [this tweet](https://twitter.com/angealbertini/status/425561082841690112/photo/1).
