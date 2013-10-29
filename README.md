jwsverify.pl
============

Perl and OpenSSL based simple JSON Web Signature (JWS) verifier.

USAGE:
------
  % jwsverify JWSFILE PKCS8PUBLICKEYFILE

DESCRIPTION
-----------
  
This Perl script verified JSON Web Signature (JWS) file with PEM public key file.
Following JWA algorithms are supported

- RS256: SHA256withRSA
- RS384: SHA384withRSA
- RS512: SHA512withRSA
- PS256: SHA256withRSAandMGF1
- PS384: SHA384withRSAandMGF1
- PS512: SHA512withRSAandMGF1
- ES256: SHA256withECDSA NIST P-256
- ES384: SHA384withECDSA NIST P-384
- ES512: SHA512withECDSA NIST P-521

LICENSE
-------
  MIT License
