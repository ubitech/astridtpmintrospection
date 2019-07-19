#!/bin/bash

tpm2_getrandom 20 -o password.bin
tpm2_pcrextend 4:sha1=$(echo -n 'GOOD STATE4'|sha1sum | tr -d ' -' |tr -d '\n') 6:sha1=$(echo -n 'GOOD STATE6'|sha1sum | tr -d ' -' |tr -d '\n')
#####tpm2_createprimary -a o -g sha1 -G rsa1024 -o primary.context  -p primary_key_pass
tpm2_createprimary -a o -o primary.context -g 0x000b -G rsa1024  -p primary_key_pass 
tpm2_pcrlist -L sha1:4,6 -o pcrs.bin
echo 'freepos token' > freepos.token
echo 'bearer token' > bearer.token

# CALCULATION OF AUTHPOLICY DIGEST USING A TRIAL SESSION.
tpm2_createpolicy -P -L sha1:4,6 -f policy.digest # -F pcrs.bin
tpm2_create -g sha256 -u obj.pub -r obj.priv -C primary.context -L policy.digest -A 'noda|adminwithpolicy|fixedparent|fixedtpm' -I password.bin -P primary_key_pass

tpm2_load -C primary.context -u obj.pub -r obj.priv -n obj.name -o password_load.ctx -P primary_key_pass

tpm2_evictcontrol -a o -c password_load.ctx -p 0x81000014

# SEALING OF PASSWORD BLOB TO PCR VALUES. LOAD IT AND MAKE IT PERSISTENT
tpm2_create -p "hex:$(xxd -p password.bin | tr -d '\n')" -g sha1 -G aes128cfb -C primary.context --privfile=aeskey.priv --pubfile=aeskey.pub -P primary_key_pass
tpm2_load -C primary.context -u aeskey.pub -r aeskey.priv -n aeskey.name -o encryption_key_load.ctx -P primary_key_pass
tpm2_evictcontrol -a o -c encryption_key_load.ctx -p 0x81000018 
tpm2_encryptdecrypt -c encryption_key_load.ctx -p "hex:$(xxd -p password.bin | tr -d '\n')" -I freepos.token -o freepos.token.enc # -i IV
tpm2_encryptdecrypt -c encryption_key_load.ctx -p "hex:$(xxd -p password.bin | tr -d '\n')" -I bearer.token -o bearer.token.enc # -i IV
tpm2_flushcontext -c primary.context
rm -f password.bin bearer.token password.token

# UNSEAL POLICY PROTECTED PASSWORD AND DECRYPT TOKENS
tpm2_unseal -c 0x81000014 -L sha1:4,6 -o password.bin
tpm2_encryptdecrypt -D -c encryption_key_load.ctx -p "hex:$(xxd -p password.bin | tr -d '\n')" -I freepos.token.enc -o freepos.token # -i IV
tpm2_encryptdecrypt -D -c encryption_key_load.ctx -p "hex:$(xxd -p password.bin | tr -d '\n')" -I bearer.token.enc -o bearer.token # -i IV
tpm2_evictcontrol -a o -c 0x81000014 
tpm2_evictcontrol -a o -c 0x81000018 
