# CBC Gagdets
This project explores the malleability of AES-CBC and outlines the importance of using a MAC when implementing a symmetric cipher.

# Disclaimer
This repository is a proof-of-concept demonstrating why using AES_CBC without a MAC is not suitable when the ciphertext can be altered by an attacker — which almost always happens, if you don't trust the means of storage / transport to store sensitive data in cleartext, you probably don't trust it not to alter it.

Nothing in this repository should be used for production (especially the `encrypt` function) or nefarious purposes (especially the function to inject a CBC gadget).

# Run
In Node.js, run `npm install && npm start`.

# Acknowledgments
I based the implementation of the CBC gadget out of the vulnerability known as [efail](https://www.efail.de) which impacted most email clients in which S/MIME or GPG encryption is implemented which did not check the MAC, therefore the ciphertext was malleable to an attacker who could MITM the encrypted emails, and the email client which displays HTML would use the injected tag to exfiltrate sensitive data.
