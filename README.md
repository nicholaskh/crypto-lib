Nodejs Crypto Lib
=================

#   HowToUse
*   install node-gyp
*   gen ssh key pair
    -   openssl genrsa -out rsa_private_key.pem -f4 1024
    -   openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
*   node-gyp configure && node-gyp build
*   run test: node test.js
