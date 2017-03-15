Nodejs Crypto Lib
=================

#   Gen rsa key pair
*   openssl genrsa -out rsa_private_key.pem -f4 -rand /dev/urandom 2048
*   openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

#   Gen ecc key pair
*   openssl ecparam -genkey -name secp256k1 -out ec_private_key.pem -text
*   openssl ec -in ec_private_key.pem -pubout -out ec_public_key.pem

#   HowToTest
*   install node-gyp
*   node-gyp configure && node-gyp build
*   run test: node test.js

