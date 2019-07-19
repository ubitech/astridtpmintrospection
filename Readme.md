
TCTI Kernel Hooking & Tracing

#Dependencies
sudo apt-get install autoconf autoconf-archive automake libtool pkg-config gcc     libssl-dev libcurl4-gnutls-dev


#Build
git clone https://github.com/tpm2-software/tpm2-tools.git
cd tpm2-tools/
git reset --hard 3.0.2-731-gf2182cf
./bootstrap 
./configure 
make
export PATH=$PATH:/root/tpm2-tools/tools

#Use tpmrm0
export TPM2TOOLS_DEVICE_FILE=/dev/tpmrm0
export TPM2TOOLS_TCTI_NAME=device
export TPM2TOOLS_ENV_TCTI="device:/dev/tpmrm0"
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"
