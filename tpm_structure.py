#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports

import ctypes
from struct import *
from pprint import *
import json

class TpmParser():
    """
    Tpm Parser class
    Created in order to parse TPM input/output and present the results
    Every TPM command and structure is based on this class
    """
    DEBUG = False

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0):
        self.offset = offset  # The current offset 
        self.tpm_command = tpm_command  # The tpm command processed
        self.has_session = has_session  # Variable indicating if we have TPM_ST_SESSIONS or TPM_ST_NO_SESSIONS
        self.session_count = session_count  # The number of session/authorization structures present
        self.response_track = dict()  # Dictionary used to store the expected response types (per pid) for every command issued to the TPM


    @staticmethod
    def delete_keys_from_json_object(dict_list_del, lst_keys):
        """
        Delete the keys present in lst_keys from the json object.
        Loops recursively over nested dictionaries and their lists.
            param: dict_list_del: The dictionary or list to be processed (json)
            param: lst_keys: The keys to be deleted
        """
        if type(dict_list_del) == list:  # in case we have a list call the function for every field of the list
            for list_field in dict_list_del:
                TpmParser.delete_keys_from_json_object(list_field, lst_keys)
        if type(dict_list_del) == dict: # in case we have a dict
            dict_foo = dict_list_del.copy() 
            for field in dict_foo.keys():
                if type(dict_foo[field]) == dict:
                    TpmParser.delete_keys_from_json_object(dict_list_del[field], lst_keys)  
                if type(dict_foo[field]) == list:
                    for list_field in dict_list_del[field]:
                        TpmParser.delete_keys_from_json_object(list_field, lst_keys)
                if field in lst_keys:
                    del dict_list_del[field]
        return dict_list_del


    @staticmethod
    def object_to_dict(my_object):
        """
        Method used to transform an object to a dictionary by json serializing and de-serializing it
        Moreover, non usefull fields are removed
            param: my_object: The object to be printed
            returns: the object as a dict
        """
        print_obj = json.loads(json.dumps(my_object, default=lambda x: x.__dict__ , ensure_ascii=False).decode('utf-8','ignore'))
        print_obj = TpmParser.delete_keys_from_json_object(print_obj,['tpm_command','offset','optional_value','selector','response_track','has_session','key_scheme_type','session_count'])
        return print_obj    


    def parse_uint64(self):
        """
        Method used to parse a uint64
        Increases the offset accordingly
            returns: the uint64
        """
        size = 8
        data = self.tpm_command[self.offset:self.offset+size]
        self.offset += size
        return  unpack('>Q',data)[0]


    def parse_uint32(self):
        """
        Method used to parse a uint32
        Increases the offset accordingly
            returns: the uint32
        """
        size = 4
        data = self.tpm_command[self.offset:self.offset+size]
        self.offset += size
        return  unpack('>I',data)[0]


    def parse_uint16(self):
        """
        Method used to parse a uint16
        Increases the offset accordingly
            returns: the uint16
        """
        size = 2
        data = self.tpm_command[self.offset:self.offset+size]
        data = unpack('>H',data)[0]
        self.offset = size + self.offset
        return data


    def parse_uint8(self):
        """
        Method used to parse a ubyte
        Increases the offset accordingly
            returns: the ubyte
        """
        size = 1
        data = ''
        data = self.tpm_command[self.offset:self.offset+size]
        data = unpack('>B',data)[0]
        self.offset = size + self.offset
        return data
  

    def translate_command_code(self, command_code, pid, write_index):
        """
        Method used to parse a command based on its command code
            param: command_code: The command code
            param: pid: The pid of the process hooked/processed
            returns: The parsed object, or None on failure
        """
        if (command_code == 'TPM_CC_CreatePrimary'):
            tpm_create_primary = TpmCreatePrimary(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_create_primary.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmCreatePrimaryResponse(session_count=tpm_create_primary.session_count)  # append expected response to list
            return tpm_create_primary

        elif (command_code == 'TPM_CC_ContextSave'):
            tpm_context_save = TpmContextSave(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_context_save.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmContextSaveResponse(session_count=tpm_context_save.session_count)  # append expected response to list
            return tpm_context_save

        elif (command_code == 'TPM_CC_Create'):
            tpm_create = TpmCreate(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_create.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmCreateResponse(session_count=tpm_create.session_count)  # append expected response to list
            return tpm_create

        elif (command_code == 'TPM_CC_ContextLoad'):
            tpm_context_load = TpmContextLoad(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_context_load.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmContextLoadResponse(session_count=tpm_context_load.session_count)  # append expected response to list
            return tpm_context_load

        elif (command_code == 'TPM_CC_Load'):
            tpm_load = TpmLoad(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_load.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmLoadResponse(session_count=tpm_load.session_count)  # append expected response to list
            return tpm_load

        elif (command_code == 'TPM_CC_RSA_Encrypt'):
            tpm_rsa_encrypt = TpmRsaEncrypt(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_rsa_encrypt.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmRsaEncryptResponse(session_count=tpm_rsa_encrypt.session_count)  # append expected response to list
            return tpm_rsa_encrypt  

        elif (command_code == 'TPM_CC_RSA_Decrypt'):
            tpm_rsa_decrypt = TpmRsaDecrypt(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_rsa_decrypt.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmRsaDecryptResponse(session_count=tpm_rsa_decrypt.session_count)  # append expected response to list
            return tpm_rsa_decrypt

        elif (command_code == 'TPM_CC_EncryptDecrypt'):
            tpm_encrypt_decrypt = TpmEncryptDecrypt(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_encrypt_decrypt.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmEncryptDecryptResponse(session_count=tpm_encrypt_decrypt.session_count)  # append expected response to list
            return tpm_encrypt_decrypt  

        elif (command_code == 'TPM_CC_EncryptDecrypt2'):
            tpm_encrypt_decrypt2 = TpmEncryptDecrypt2(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_encrypt_decrypt2.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmEncryptDecrypt2Response(session_count=tpm_encrypt_decrypt2.session_count)  # append expected response to list
            return tpm_encrypt_decrypt2 

        elif (command_code == 'TPM_CC_ReadPublic'):
            tpm_read_public = TpmReadPublic(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_read_public.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmReadPublicResponse(session_count=tpm_read_public.session_count)  # append expected response to list
            return tpm_read_public 

        elif (command_code == 'TPM_CC_GetCapability'):
            tpm_get_capability = TpmGetCapability(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_get_capability.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmGetCapabilityResponse(session_count=tpm_get_capability.session_count)  # append expected response to list
            return tpm_get_capability 

        elif (command_code == 'TPM_CC_PCR_Read'):
            tpm_pcr_read = TpmPcrRead(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_pcr_read.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmPcrReadResponse(session_count=tpm_pcr_read.session_count)  # append expected response to list
            return tpm_pcr_read

        elif (command_code == 'TPM_CC_StartAuthSession'):
            tpm_start_auth_session = TpmStartAuthSession(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_start_auth_session.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmStartAuthSessionResponse(session_count=tpm_start_auth_session.session_count)  # append expected response to list
            return tpm_start_auth_session  

        elif (command_code == 'TPM_CC_PolicyPCR'):
            tpm_policy_pcr = TpmPolicyPcr(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_policy_pcr.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmPolicyPcrResponse(session_count=tpm_policy_pcr.session_count)  # append expected response to list
            return tpm_policy_pcr  

        elif (command_code == 'TPM_CC_PolicyGetDigest'):
            tpm_policy_get_digest = TpmPolicyGetDigest(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_policy_get_digest.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmPolicyGetDigestResponse(session_count=tpm_policy_get_digest.session_count)  # append expected response to list
            return tpm_policy_get_digest 

        elif (command_code == 'TPM_CC_EvictControl'):
            tpm_evict_control = TpmEvictControl(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_evict_control.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmEvictControlResponse(session_count=tpm_evict_control.session_count)  # append expected response to list
            return tpm_evict_control   

        elif (command_code == 'TPM_CC_Unseal'):
            tpm_unseal = TpmUnseal(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_unseal.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmUnsealResponse(session_count=tpm_unseal.session_count)  # append expected response to list
            return tpm_unseal

        elif (command_code == 'TPM_CC_FlushContext'):
            tpm_flush_context = TpmFlushContext(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_flush_context.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmFlushContextResponse(session_count=tpm_flush_context.session_count)  # append expected response to list
            return tpm_flush_context    

        elif (command_code == 'TPM_CC_PCR_Extend'):
            tpm_pcr_extend = TpmPcrExtend(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_pcr_extend.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmPcrExtendResponse(session_count=tpm_pcr_extend.session_count)  # append expected response to list
            return tpm_pcr_extend 

        elif (command_code == 'TPM_CC_GetRandom'):
            tpm_get_random = TpmGetRandom(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_get_random.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmGetRandomResponse(session_count=tpm_get_random.session_count)  # append expected response to list
            return tpm_get_random

        elif (command_code == 'TPM_CC_Hash'):
            tpm_hash = TpmHash(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_hash.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmHashResponse(session_count=tpm_hash.session_count)  # append expected response to list
            return tpm_hash 

        elif (command_code == 'TPM_CC_Commit'):
            tpm_commit = TpmCommit(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_commit.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmCommitResponse(session_count=tpm_commit.session_count)  # append expected response to list
            return tpm_commit 

        elif (command_code == 'TPM_CC_Sign'):
            tpm_sign = TpmSign(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_sign.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmSignResponse(session_count=tpm_sign.session_count)  # append expected response to list
            return tpm_sign

        elif (command_code == 'TPM_CC_MakeCredential'):
            tpm_make_credential = TpmMakeCredential(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_make_credential.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmMakeCredentialResponse(session_count=tpm_make_credential.session_count)  # append expected response to list
            return tpm_make_credential 

        elif (command_code == 'TPM_CC_ActivateCredential'):
            tpm_activate_credential = TpmActivateCredential(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_activate_credential.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmActivateCredentialResponse(session_count=tpm_activate_credential.session_count)  # append expected response to list
            return tpm_activate_credential 

        elif (command_code == 'TPM_CC_PolicySecret'):
            tpm_policy_secret = TpmPolicySecret(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_policy_secret.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmPolicySecretResponse(session_count=tpm_policy_secret.session_count)  # append expected response to list
            return tpm_policy_secret 

        elif (command_code == 'TPM_CC_Certify'):
            tpm_certify = TpmCertify(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_certify.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmCertifyResponse(session_count=tpm_certify.session_count)  # append expected response to list
            return tpm_certify 

        elif (command_code == 'TPM_CC_VerifySignature'):
            tpm_verify_signature = TpmVerifySignature(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_verify_signature.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmVerifySignatureResponse(session_count=tpm_verify_signature.session_count)  # append expected response to list
            return tpm_verify_signature 

        elif (command_code == 'TPM_CC_ECDH_KeyGen'):
            tpm_ecdh_keygen = TpmEcdhKeygen(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_ecdh_keygen.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmEcdhKeygenResponse(session_count=tpm_ecdh_keygen.session_count)  # append expected response to list
            return tpm_ecdh_keygen 

        elif (command_code == 'TPM_CC_ECDH_ZGen'):
            tpm_ecdh_zgen = TpmEcdhZgen(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_ecdh_zgen.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmEcdhZgenResponse(session_count=tpm_ecdh_zgen.session_count)  # append expected response to list
            return tpm_ecdh_zgen 

        elif (command_code == 'TPM_CC_ECC_Parameters'):
            tpm_ecc_parameters = TpmEccParameters(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_ecc_parameters.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmEccParametersResponse(session_count=tpm_ecc_parameters.session_count)  # append expected response to list
            return tpm_ecc_parameters 

        elif (command_code == 'TPM_CC_EC_Ephemeral'):
            tpm_ec_ephemeral = TpmEcEphemeral(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_ec_ephemeral.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmEcEphemeralResponse(session_count=tpm_ec_ephemeral.session_count)  # append expected response to list
            return tpm_ec_ephemeral 

        elif (command_code == 'TPM_CC_ZGen_2Phase'):
            tpm_zgen_2phase = TpmZgen2Phase(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_zgen_2phase.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmZgen2PhaseResponse(session_count=tpm_zgen_2phase.session_count)  # append expected response to list
            return tpm_zgen_2phase 

        elif (command_code == 'TPM_CC_CertifyCreation'):
            tpm_certify_creation = TpmCertifyCreation(tpm_command=self.tpm_command, offset=self.offset, has_session=self.has_session)
            tpm_certify_creation.parse()
            if pid not in self.response_track:
                self.response_track[pid] = dict()  # Initialize list for specific pid if not already initialized
            self.response_track[pid][write_index] = TpmCertifyCreationResponse(session_count=tpm_certify_creation.session_count)  # append expected response to list
            return tpm_certify_creation 

        else:
            return None


    def parse(self, pid, operation, write_index=0, read_index=0):
        """
        Method used to parse the tpm command
            param: pid: The pid of the process hooked
            param: operation: Read/Write
            returns: A dictionary containing the command header and parsed command
        """

        try:
            # Command Parsing
            if operation == 'W':
                # Parse Command Header
                tpm_command_header = TpmCommandHeader(tpm_command=self.tpm_command, offset=self.offset)
                self.offset = tpm_command_header.parse()
                self.has_session = tpm_command_header.tpmi_st_command_tag == 'TPM_ST_SESSIONS'
                dict_header = TpmParser.object_to_dict(tpm_command_header)
                if self.DEBUG:
                    print(tpm_command_header)  #!debug

                # Parse TPM Command  
                tpm_command = self.translate_command_code(tpm_command_header.command_code.tpm_cc,pid,write_index)
                dict_command = TpmParser.object_to_dict(tpm_command)
                return {"Command Header":dict_header,"Parsed Command":dict_command}

        except Exception as ex:
            if (self.DEBUG):
                print("[E] Exception at command processing: {}".format(ex))  #!debug
                return None

        try:
            # Response Parsing
            if operation == 'R' and pid in self.response_track and self.response_track[pid]:
                # Parse Response Header
                tpm_response_header = TpmResponseHeader(tpm_command=self.tpm_command, offset=self.offset) 
                self.offset = tpm_response_header.parse()
                dict_header = TpmParser.object_to_dict(tpm_response_header)
                if self.DEBUG:
                    print(tpm_response_header)  #!debug

                if read_index not in self.response_track[pid]:
                    return {"Command Header":dict_header}

                if tpm_response_header.response_code!="TPM_RC_SUCCESS":  # Case of Error Response
                    del self.response_track[pid][read_index]  # Delete object from list
                    return {"Command Header":dict_header}
                else:
                    # Parse response
                    tpm_command = self.response_track[pid][read_index]  # Read the type of response expected
                    tpm_command.tpm_command = self.tpm_command
                    tpm_command.offset = self.offset
                    tpm_command.has_session = tpm_response_header.tag == 'TPM_ST_SESSIONS'
                    tpm_command.parse()
                    dict_command = TpmParser.object_to_dict(tpm_command)
                    del self.response_track[pid][read_index]  # Delete object from list after parsing
                    return {"Command Header":dict_header,"Parsed Command":dict_command}

        except Exception as ex:
            if (self.DEBUG):
                print("[E] Exception at Response processing: {}".format(ex))  #!debug
            del self.response_track[pid][read_index]  # Delete object from list upon exception
            return None



# -------------------------------------------------------- TPM HEADER -------------------------------------------------

class TpmCommandHeader(TpmParser):
    """
    Header parsing class
    Page 5 Part 3 (Header validation)
        -- The TPM shall successfully unmarshal a TPMI_ST_COMMAND_TAG and verify that it is either TPM_ST_SESSIONS or TPM_ST_NO_SESSIONS (TPM_RC_BAD_TAG).
        -- The TPM shall successfully unmarshal a UINT32 as the commandSize...
        -- The TPM shall successfully unmarshal a TPM_CC and verify that the command is implemented (TPM_RC_COMMAND_CODE)
    Page 54 Practical guide to TPM
        -- tag: Identifies whether the command contains sessions that is, whether it contains an authorization area
        -- commandSize: The size of the command byte stream, including all fields of the header.
        -- commandCode: Identifies the TPM command to be executed, and controls the interpretation of the rest of the command byte stream.
    """

    def __init__(self, tpm_command, offset, has_session=False, session_count=0, tpmi_st_command_tag='', command_size=0, command_code=''):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.tpmi_st_command_tag = tpmi_st_command_tag
        self.command_size = command_size
        self.command_code = command_code


    def __str__(self):
        return '[i] TPM COMMAND HEADER:\n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse_tpmi_st_command(self):
        """
        Page 87 part 2 (TPMI_ST_COMMAND_TAG)
        Possible Values:
            TPM_ST_NO_SESSIONS  # page 43 Part 2
            TPM_ST_SESSIONS  # page 43 Part 2
            TPM_RC_BAD_TAG  # page 37 Part 2
        """
        TPMI_ST_COMMAND_TAG = {0x8001:'TPM_ST_NO_SESSIONS',0x8002:'TPM_ST_SESSIONS',0x01E:'TPM_RC_BAD_TAG'}
        return TPMI_ST_COMMAND_TAG[self.parse_uint16()]
        

    def parse(self):
        self.tpmi_st_command_tag = self.parse_tpmi_st_command()
        self.command_size = self.parse_uint32()
        self.command_code = TpmCc(self.tpm_command, self.offset)
        self.offset = self.command_code.parse()
        return self.offset



class TpmResponseHeader(TpmParser):
    """
    Page 55 Practical guide to TPM
        -- tag: TPM_ST
        -- responseSize: UINT32
        -- responseCode: TPMRC
    """

    def __init__(self, tpm_command, offset, has_session=False, session_count=0, tag='', response_size=0, response_code=''):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.tag = tag
        self.response_size = response_size
        self.response_code = response_code


    def __str__(self):
        return '[i] TPM RESPONSE HEADER:\n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse_tpm_response_code(self):
        rc = self.parse_uint32()
        if rc == 0x0000:
            return "TPM_RC_SUCCESS"
        return hex(rc)

    def parse(self):
        self.tag = TpmSt(self.tpm_command, self.offset)
        self.offset = self.tag.parse()
        self.response_size = self.parse_uint32()
        self.response_code = self.parse_tpm_response_code()
        return self.offset

# -------------------------------------------------------- END OF TPM HEADER -------------------------------------------------



# -------------------------------------------------------- TPM COMMANDS -------------------------------------------------

class TpmCreatePrimary(TpmParser):
    """
    Page 272 Part 3 (TPM2_CreatePrimary) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_CreatePrimary
        
        -- TPMI_RH_HIERARCHY+: @primaryHandle: TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL    Auth Index:: 1 Auth Role:: USER
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_RH_HIERARCHY)
        ========================================================================
        -- TPM2B_SENSITIVE_CREATE: inSensitive: the sensitive data, see TPM 2.0 Part 1 Sensitive Values
        -- TPM2B_PUBLIC: inPublic: the public template
        -- TPM2B_DATA: outsideInfo: data that will be included in the creation data for this object to provide permanent, verifiable linkage between this object and some object owner data
        -- TPML_PCR_SELECTION: creationPCR: PCR that will be used in creation data
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, primary_handle=None, authorization=None, in_sensitive=None, in_public=None, outside_info=None, creation_pcr = None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.primary_handle = primary_handle
        self.authorization = authorization
        self.in_sensitive = in_sensitive
        self.in_public = in_public
        self.outside_info = outside_info
        self.creation_pcr = creation_pcr
        if (self.DEBUG):
            print(" [i] TPM2_CreatePrimary OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_CreatePrimary: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse @primaryHandle
        self.primary_handle = TpmiRhHierarchy(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.primary_handle.parse()

        # Parse Authorization_structure
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse inSensitive
        self.in_sensitive = Tpm2bSensitiveCreate(self.tpm_command, self.offset)
        self.offset = self.in_sensitive.parse()

        # Parse inPublic
        self.in_public = Tpm2bPublic(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.in_public.parse()

        # Parse outsideInfo
        self.outside_info = Tpm2bData(self.tpm_command, self.offset)
        self.offset = self.outside_info.parse()

        # Parse creationPCR
        self.creation_pcr = TpmlPcrSelection(self.tpm_command,self.offset)
        self.offset = self.creation_pcr.parse()
        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_CreatePrimary: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug 
        return self.offset



class TpmCreatePrimaryResponse(TpmParser):
    """
    Page 272 Part 3 (TPM2_CreatePrimary Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        -- TPM_HANDLE: objectHandle: handle of type TPM_HT_TRANSIENT for created Primary Object
        ========================================================================
        #Parameter area size UINT32
        -- TPM2B_PUBLIC: outPublic: the public portion of the created object
        -- TPM2B_CREATION_DATA: creationData: contains a TPMT_CREATION_DATA
        -- TPM2B_DIGEST: creationHash: digest of creationData using nameAlg of outPublic
        -- TPMT_TK_CREATION: creationTicket: ticket used by TPM2_CertifyCreation() to validate that the creation data was produced by the TPM
        -- TPM2B_NAME: name: the name of the created object
        # Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, object_handle=0, parameter_size=0, out_public=None, creation_data=None, creation_hash=None, creation_ticket=None, name=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.object_handle = object_handle
        self.parameter_size = parameter_size
        self.out_public = out_public
        self.creation_data = creation_data
        self.creation_hash = creation_hash
        self.creation_ticket = creation_ticket
        self.name = name
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_CreatePrimary Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_CreatePrimary Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse objectHandle+
        self.object_handle = hex(self.parse_uint32())

        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse out_public
        self.out_public = Tpm2bPublic(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.out_public.parse()

        # Parse creation_data
        self.creation_data = Tpm2bCreationData(self.tpm_command, self.offset)
        self.offset = self.creation_data.parse()

        # Parse creation_hash
        self.creation_hash = Tpm2bDigest(self.tpm_command, self.offset) 
        self.offset = self.creation_hash.parse()
        if self.creation_hash.buf:
            self.creation_hash.buf = "0x"+self.creation_hash.buf.encode('hex')

        # Parse creation_ticket
        self.creation_ticket = TpmtTkCreation(self.tpm_command, self.offset)
        self.offset = self.creation_ticket.parse()

        # Parse name
        self.name = Tpm2bName(self.tpm_command, self.offset)
        self.offset = self.name.parse()


        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_CreatePrimaryR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmCreate(TpmParser):
    """
    Page 48 Part 3 (TPM2_Create) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_Create
        
        -- TPMI_DH_OBJECT+: @parentHandle: handle of parent for new object Auth Index:: 1 Auth Role:: USER
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
                +TPM_RH_NULL: the conditional value
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        ========================================================================
        -- TPM2B_SENSITIVE_CREATE: inSensitive: the sensitive data, see TPM 2.0 Part 1 Sensitive     Values
        -- TPM2B_PUBLIC: inPublic: the public template
        -- TPM2B_DATA:: outsideInfo: data that will be included in the creation data for this object to provide permanent, verifiable linkage between this object and some object owner data
        -- TPML_PCR_SELECTION: creationPCR: PCR that will be used in creation data
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parent_handle=0, authorization=None, in_sensitive=None, in_public=None, outside_info=None, creation_pcr=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parent_handle = parent_handle
        self.authorization = authorization
        self.in_sensitive = in_sensitive
        self.in_public = in_public
        self.outside_info = outside_info
        self.creation_pcr = creation_pcr
        if (self.DEBUG):
            print(" [i] TPM2_Create OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Create: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parentHandle
        self.parent_handle = hex(self.parse_uint32())

        # Parse Authorization_structure
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse inSensitive
        self.in_sensitive = Tpm2bSensitiveCreate(self.tpm_command, self.offset)
        self.offset = self.in_sensitive.parse()

        # Parse inPublic
        self.in_public = Tpm2bPublic(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.in_public.parse()

        # Parse outsideInfo
        self.outside_info = Tpm2bData(self.tpm_command, self.offset)
        self.offset = self.outside_info.parse()

        # Parse creationPCR
        self.creation_pcr = TpmlPcrSelection(self.tpm_command,self.offset)
        self.offset = self.creation_pcr.parse()
        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_Create: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug 
        return self.offset



class TpmCreateResponse(TpmParser):
    """
    Page 48 Part 3 (TPM2_Create Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #Parameter area size UINT32
        -- TPM2B_PRIVATE: outprivate: the private portion of the object
        -- TPM2B_PUBLIC: outPublic: the public portion of the created object
        -- TPM2B_CREATION_DATA: creationData: contains a TPMS_CREATION_DATA
        -- TPM2B_DIGEST: creationHash: digest of creationData using nameAlg of outPublic
        -- TPMT_TK_CREATION: creationTicket: ticket used by TPM2_CertifyCreation() to validate that the creation data was produced by the TPM
        # Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, out_private=None, out_public=None, creation_data=None, creation_hash=None, creation_ticket=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.out_private = out_private
        self.out_public = out_public
        self.creation_data = creation_data
        self.creation_hash = creation_hash
        self.creation_ticket = creation_ticket
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_Create Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Create Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse outprivate
        self.out_private = Tpm2bPrivate(self.tpm_command, self.offset)
        self.offset = self.out_private.parse()

        # Parse out_public
        self.out_public = Tpm2bPublic(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.out_public.parse()

        # Parse creation_data
        self.creation_data = Tpm2bCreationData(self.tpm_command, self.offset)
        self.offset = self.creation_data.parse()

        # Parse creation_hash
        self.creation_hash = Tpm2bDigest(self.tpm_command, self.offset) 
        self.offset = self.creation_hash.parse()
        if self.creation_hash.buf:
            self.creation_hash.buf = "0x"+self.creation_hash.buf.encode('hex')

        # Parse creation_ticket
        self.creation_ticket = TpmtTkCreation(self.tpm_command, self.offset)
        self.offset = self.creation_ticket.parse()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_CreateR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmContextSave(TpmParser):
    """
    Page 319 Part 3 (TPM2_ContextSave) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_ContextSave
        
        -- TPMI_DH_CONTEXT: saveHandle: handle of the resource to save. Auth Index: None
            Possible Values Page 80  Part 2
            {HMAC_SESSION_FIRST : HMAC_SESSION_LAST}
            {POLICY_SESSION_FIRST:POLICY_SESSION_LAST}
            {TRANSIENT_FIRST:TRANSIENT_LAST}
            #TPM_RC_VALUE
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, save_handle=0):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.save_handle = save_handle

        if (self.DEBUG):
            print(" [i] TPM2_ContextSave OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_TpmContextSave: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.save_handle = hex(self.parse_uint32())
        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ContextSave: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmContextSaveResponse(TpmParser):
    """
    Page 319 Part 3 (TPM2_ContextSave Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- TPMS_CONTEXT: context
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, context=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.context = context
        if (self.DEBUG):
            print(" [i] TPM2_ContextSave Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ContextSave Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.context = TpmsContext(self.tpm_command, self.offset)
        self.offset = self.context.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ContextSaveR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmContextLoad(TpmParser):
    """
    Page 322 Part 3 (TPM2_ContextLoad) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_NO_SESSIONS
        -- UINT32 commandSize:
        -- TPM_CC: commandCode: TPM_CC_ContextLoad
        
        -- TPMS_CONTEXT: context: the context blob
        ========================================================================
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, context=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.context = context

        if (self.DEBUG):
            print(" [i] TPM2_ContextLoad OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ContextLoad: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.context = TpmsContext(self.tpm_command, self.offset)
        self.offset = self.context.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ContextLoad: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmContextLoadResponse(TpmParser):
    """
    Page 322 Part 3 (TPM2_ContextLoad Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- TPMI_DH_CONTEXT: loadedHandle: the handle assigned to the resource after it has been successfully loaded
            Possible Values Page 80  Part 2
            {HMAC_SESSION_FIRST : HMAC_SESSION_LAST}
            {POLICY_SESSION_FIRST:POLICY_SESSION_LAST}
            {TRANSIENT_FIRST:TRANSIENT_LAST}
            #TPM_RC_VALUE
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, loaded_handle=0):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.loaded_handle = loaded_handle
        if (self.DEBUG):
            print(" [i] TPM2_ContextLoad Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ContextLoad Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.loaded_handle = hex(self.parse_uint32())

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ContextLoadR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmLoad(TpmParser):
    """
    Page 51 Part 3 (TPM2_Load) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize:
        -- TPM_CC: commandCode: TPM_CC_Load
        
        -- TPMI_DH_OBJECT: @parentHandle: TPM handle of parent key; shall not be a reserved handle. Auth Index: 1. Auth Role: USER
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        ========================================================================
        -- TPM2B_PRIVATE: inPrivate: the private portion of the object
        -- TPM2B_PUBLIC: inPublic: the public portion of the object
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parent_handle=0, authorization=None, in_private=None, in_public=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parent_handle = parent_handle
        self.authorization = authorization
        self.in_private = in_private
        self.in_public = in_public

        if (self.DEBUG):
            print(" [i] TPM2_Load OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Load: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parentHandle
        self.parent_handle = hex(self.parse_uint32())

        # Parse Authorization_structure
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse inPrivate
        self.in_private = Tpm2bPrivate(self.tpm_command, self.offset)
        self.offset = self.in_private.parse()

        # Parse inPublic
        self.in_public = Tpm2bPublic(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.in_public.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_Load: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmLoadResponse(TpmParser):
    """
    Page 51 Part 3 (TPM2_Load Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        -- TPM_HANDLE: objectHandle: handle of type TPM_HT_TRANSIENT for the loaded object 
        ========================================================================
        #Parameter area size UINT32
        -- TPM2B_NAME: name: Name of the loaded object
        # Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, object_handle=0, parameter_size=0, name=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.object_handle = object_handle
        self.parameter_size = parameter_size
        self.name = name
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_Load Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Load Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse objectHandle+
        self.object_handle = hex(self.parse_uint32())

        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse name
        self.name = Tpm2bName(self.tpm_command, self.offset)
        self.offset = self.name.parse()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_LoadR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmRsaEncrypt(TpmParser):
    """
    Page 87 Part 3 (TPM2_RSA_Encrypt) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS if an audit, encrypt, or decrypt session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_RSA_Encrypt
        
        -- TPMI_DH_OBJECT: keyHandle: reference to public portion of RSA key to use for encryption Auth Index: None
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
        -- TPM2B_PUBLIC_KEY_RSA: message: message to be encrypted. NOTE: The data type was chosen because it limits the overall size of the input to no greater than the size of the largest RSA public key
        -- TPMT_RSA_DECRYPT+: inScheme: the padding scheme to use if scheme associated with keyHandle is TPM_ALG_NULL
        -- TPM2B_DATA: label: optional label L to be associated with the message. Size of the buffer is zero if no label is present
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, key_handle=0, message=None, in_scheme=None, label=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.key_handle = key_handle
        #self.authorization = authorization
        self.message = message
        self.in_scheme = in_scheme
        self.label = label
        if (self.DEBUG):
            print(" [i] TPM2_RSA_Encrypt OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_RSA_Encrypt: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse keyHandle
        self.key_handle = hex(self.parse_uint32())

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        # Parse message
        self.message = Tpm2bPublicKeyRsa(self.tpm_command,self.offset)
        self.offset = self.message.parse()

        # Parse in_scheme 
        self.in_scheme = TpmtRsaDecrypt(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.in_scheme.parse()

        # Parse label
        self.label = Tpm2bData(self.tpm_command, self.offset)
        self.offset = self.label.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_RSA_Encrypt: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmRsaEncryptResponse(TpmParser):
    """
    Page 87 Part 3 (TPM2_RSA_Encrypt Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        -- TPM2B_PUBLIC_KEY_RSA: outData: encrypted output
        #IF TPM_ST_SESSIONS: Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, out_data=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.parameter_size = parameter_size
        self.out_data = out_data
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_RSA_Encrypt Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_RSA_Encrypt Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        if self.has_session: #case we have TPM_ST_SESSIONS
            # parse parameterSize
            self.parameter_size = self.parse_uint32()

        # Parse outData
        self.out_data = Tpm2bPublicKeyRsa(self.tpm_command, self.offset)
        self.offset = self.out_data.parse()

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_RSA_EncryptR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmRsaDecrypt(TpmParser):
    """ 
    Page 90 Part 3 (TPM2_RSA_Decrypt) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_RSA_Decrypt
        
        -- TPMI_DH_OBJECT: @keyHandle: RSA key to use for decryption. Auth Index: 1 Auth Role: USER
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        ========================================================================
        -- TPM2B_PUBLIC_KEY_RSA: cipherText: cipher text to be decrypted NOTE: An encrypted RSA data block is the size of the public modulus.
        -- TPMT_RSA_DECRYPT+: inScheme: the padding scheme to use if scheme associated with keyHandle is TPM_ALG_NULL
        -- TPM2B_DATA: label: label whose association with the message is to be verified
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, key_handle=0, authorization=None, cipher_text=None, in_scheme=None, label=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.key_handle = key_handle
        self.authorization = authorization
        self.cipher_text = cipher_text
        self.in_scheme = in_scheme
        self.label = label
        if (self.DEBUG):
            print(" [i] TPM2_RSA_Decrypt OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_RSA_Decrypt: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse keyHandle
        self.key_handle = hex(self.parse_uint32())

        # Parse authorization
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse cipherText
        self.cipher_text = Tpm2bPublicKeyRsa(self.tpm_command,self.offset)
        self.offset = self.cipher_text.parse()


        # Parse inScheme 
        self.in_scheme = TpmtRsaDecrypt(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.in_scheme.parse()

        # Parse label
        self.label = Tpm2bData(self.tpm_command, self.offset)
        self.offset = self.label.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_RSA_Decrypt: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmRsaDecryptResponse(TpmParser):
    """
    Page 90 Part 3 (TPM2_RSA_Decrypt Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- #Parameter area size UINT32
        -- TPM2B_PUBLIC_KEY_RSA: message: decrypted output
        -- # Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, message=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.message = message
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_RSA_Decrypt Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_RSA_Decrypt Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse message
        self.message = Tpm2bPublicKeyRsa(self.tpm_command, self.offset)
        self.offset = self.message.parse()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_RSA_DecryptR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEncryptDecrypt(TpmParser):
    """ 
    Page 107 Part 3 (TPM2_EncryptDecrypt) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_RSA_Decrypt
        
        -- TPMI_DH_OBJECT: @keyHandle: the symmetric key used for the operation Auth Index: 1 Auth Role: USER
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        ========================================================================
        -- TPMI_YES_NO ((BYTE YES-->1 OR NO-->0): decrypt: if YES, then the operation is decryption; if NO, the operation is encryption
        -- TPMI_ALG_SYM_MODE+ (TPM_ALG_!ALG.SE+ NULL) : mode: symmetric mode. this field shall match the default mode of the key or be TPM_ALG_NULL.
        -- TPM2B_IV: ivIn: an initial value as required by the algorithm
        -- TPM2B_MAX_BUFFER: inData: the data to be encrypted/decrypted
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, key_handle=0, authorization=None, decrypt='', mode=None, iv_in=None, in_data=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.key_handle = key_handle
        self.authorization = authorization
        self.decrypt = decrypt
        self.mode = mode
        self.iv_in = iv_in
        self.in_data = in_data
        if (self.DEBUG):
            print(" [i] TPM2_EncryptDecrypt OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_EncryptDecrypt: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse keyHandle
        self.key_handle = hex(self.parse_uint32())

        # Parse authorization
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse decrypt
        decrypt_value = self.parse_uint8()
        if decrypt_value == 1:
            self.decrypt = 'Decrypt'
        elif decrypt_value == 0:
            self.decrypt = 'Encrypt'

        # Parse mode 
        self.mode =TpmAlg(self.tpm_command, self.offset, alg_types=['symmetric','encryption'], optional_value=True)
        self.offset = self.mode.parse()

        # Parse ivIn
        self.iv_in = Tpm2bIv(self.tpm_command, self.offset)
        self.offset = self.iv_in.parse()

        # Parse inData
        self.in_data = Tpm2bMaxBuffer(self.tpm_command, self.offset)
        self.offset = self.in_data.parse()
        if self.in_data.buf:
            self.in_data.buf = "0x"+self.in_data.buf.encode('hex')

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_EncryptDecrypt: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEncryptDecryptResponse(TpmParser):
    """
    Page 107 Part 3 (TPM2_EncryptDecrypt Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- #Parameter area size UINT32
        -- TPM2B_MAX_BUFFER: outData: encrypted or decrypted output
        -- TPM2B_IV: ivOut: chaining value to use for IV in next round
        -- # Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, out_data=None, iv_out=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.out_data = out_data
        self.iv_out = iv_out
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_EncryptDecrypt Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_EncryptDecrypt Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse outData
        self.out_data = Tpm2bMaxBuffer(self.tpm_command, self.offset)
        self.offset = self.out_data.parse()
        if self.out_data.buf:
            self.out_data.buf = "0x"+self.out_data.buf.encode('hex')

        # Parse ivOut
        self.iv_out = Tpm2bIv(self.tpm_command,self.offset)
        self.offset = self.iv_out.parse()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_EncryptDecryptR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEncryptDecrypt2(TpmParser):
    """ 
    Page 110 Part 3 (TPM2_EncryptDecrypt2)
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_EncryptDecrypt2
        
        -- TPMI_DH_OBJECT: @keyHandle: the symmetric key used for the operation. Auth Index: 1. Auth Role: USER
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        ========================================================================
        -- TPM2B_MAX_BUFFER: inData: the data to be encrypted/decrypted
        -- TPMI_YES_NO ((BYTE YES-->1 OR NO-->0): decrypt: if YES, then the operation is decryption; if NO, the operation is encryption
        -- TPMI_ALG_SYM_MODE+ (TPM_ALG_!ALG.SE+ NULL) : mode: symmetric mode. this field shall match the default mode of the key or be TPM_ALG_NULL.
        -- TPM2B_IV: ivIn: an initial value as required by the algorithm
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, key_handle=0, authorization=None, in_data=None, decrypt='', mode=None, iv_in=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.key_handle = key_handle
        self.authorization = authorization
        self.in_data = in_data
        self.decrypt = decrypt
        self.mode = mode
        self.iv_in = iv_in
        if (self.DEBUG):
            print(" [i] TPM2_EncryptDecrypt2 OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_EncryptDecrypt2: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse keyHandle
        self.key_handle = hex(self.parse_uint32())

        # Parse authorization
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse inData
        self.in_data = Tpm2bMaxBuffer(self.tpm_command, self.offset)
        self.offset = self.in_data.parse()
        if self.in_data.buf:
            self.in_data.buf = "0x"+self.in_data.buf.encode('hex')
        # Parse decrypt
        decrypt_value = self.parse_uint8()
        if decrypt_value == 1:
            self.decrypt = 'Decrypt'
        elif decrypt_value == 0:
            self.decrypt = 'Encrypt'

        # Parse mode 
        self.mode =TpmAlg(self.tpm_command, self.offset, alg_types=['symmetric','encryption'], optional_value=True)
        self.offset = self.mode.parse()

        # Parse ivIn
        self.iv_in = Tpm2bIv(self.tpm_command, self.offset)
        self.offset = self.iv_in.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_EncryptDecrypt2: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEncryptDecrypt2Response(TpmParser):
    """
    Page 110 Part 3 (TPM2_EncryptDecrypt2 Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- #Parameter area size UINT32
        -- TPM2B_MAX_BUFFER: outData: encrypted or decrypted output
        -- TPM2B_IV: ivOut: chaining value to use for IV in next round
        -- # Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, out_data=None, iv_out=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.out_data = out_data
        self.iv_out = iv_out
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_EncryptDecrypt2 Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_EncryptDecrypt2 Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse outData
        self.out_data = Tpm2bMaxBuffer(self.tpm_command, self.offset)
        self.offset = self.out_data.parse()
        if self.out_data.buf:
            self.out_data.buf = "0x"+self.out_data.buf.encode('hex')

        # Parse ivOut
        self.iv_out = Tpm2bIv(self.tpm_command,self.offset)
        self.offset = self.iv_out.parse()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_EncryptDecrypt2R: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmReadPublic(TpmParser):
    """ 
    Page 58 Part 3 (TPM2_ReadPublic) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS if an audit or encrypt session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_ReadPublic
        
        -- TPMI_DH_OBJECT: @objectHandle: TPM handle of an object. Auth Index: None
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, object_handle=0):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.object_handle = object_handle
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_ReadPublic OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ReadPublic: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse objectHandle
        self.object_handle = hex(self.parse_uint32())


        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ReadPublic: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmReadPublicResponse(TpmParser):
    """
    Page 58 Part 3 (TPM2_ReadPublic Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        -- TPM2B_PUBLIC: outPublic: structure containing the public area of an object
        -- TPM2B_NAME: name: name of the object
        -- TPM2B_NAME: qualifiedName: the Qualified Name of the object
        #IF TPM_ST_SESSIONS: Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, out_public=None, name=None, qualified_name=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.parameter_size = parameter_size
        self.out_public = out_public
        self.name = name
        self.qualified_name = qualified_name
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_ReadPublic Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ReadPublic Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            # parse parameterSize
            self.parameter_size = self.parse_uint32()

        # parse outPublic
        self.out_public = Tpm2bPublic(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.out_public.parse()

        # parse name
        self.name = Tpm2bName(self.tpm_command,self.offset)
        self.offset = self.name.parse()

        # parse qualifiedName
        self.qualified_name = Tpm2bName(self.tpm_command,self.offset)
        self.offset = self.qualified_name.parse()

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ReadPublicR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmGetCapability(TpmParser):
    """ 
    Page 344 Part 3 (TPM2_GetCapability) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS if an audit session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_GetCapability

        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
        -- TPM_CAP: capability: group selection; determines the format of the response
        -- UINT32: property: further definition of information
        -- UINT32: propertyCount: number of properties of the indicated type to return
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, capability=None, cap_property=0, property_count=0 ):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.authorization = authorization
        self.capability = capability
        self.cap_property = cap_property
        self.property_count = property_count
        if (self.DEBUG):
            print(" [i] TPM2_GetCapability OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_GetCapability: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        # Parse capability
        self.capability = TpmCap(self.tpm_command, self.offset)
        self.offset = self.capability.parse()

        # Parse property
        self.cap_property = self.parse_uint32()

        # Parse property_count
        self.property_count = self.parse_uint32()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_GetCapability: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmGetCapabilityResponse(TpmParser):
    """
    Page 344 Part 3 (TPM2_GetCapability Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        -- TPMI_YES_NO  ((BYTE YES-->1 OR NO-->0): moreData: flag to indicate if there are more values of this type
        -- TPMS_CAPABILITY_DATA: capabilityData: the capability data
        #IF TPM_ST_SESSIONS: Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, more_data='', capability_data=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.parameter_size = parameter_size
        self.more_data = more_data
        self.capability_data = capability_data
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_GetCapability Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_GetCapability Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            # Parse parameterSize
            self.parameter_size = self.parse_uint32()

        # Parse moreData
        more_data = self.parse_uint8()
        if more_data == 1:
            self.more_data = 'YES'
        elif more_data == 0:
            self.more_data = 'NO'

        # Parse capabilityData
        self.capability_data = TpmsCapabilityData(self.tpm_command, self.offset)
        self.offset = self.capability_data.parse()

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_GetCapabilityR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmStartAuthSession(TpmParser):
    """ 
    Page 40 Part 3 (TPM2_StartAuthSession) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS if an audit, decrypt, or encrypt session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_StartAuthSession

        -- TPMI_DH_OBJECT+: tpmKey: handle of a loaded decrypt key used to encrypt salt may be TPM_RH_NULL Auth Index: None                
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
                +TPM_RH_NULL: the conditional value
        -- TPMI_DH_ENTITY+: bind: entity providing the authValue may be TPM_RH_NULL Auth Index: None
        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
        -- TPM2B_NONCE (TPM2B_DIGEST): nonceCaller: initial nonceCaller, sets nonceTPM size for the session shall be at least 16 octets
        -- TPM2B_ENCRYPTED_SECRET: encryptedSalt: value encrypted according to the type of tpmKey. If tpmKey is TPM_RH_NULL, this shall be the Empty Buffer.
        -- TPM_SE: sessionType: indicates the type of the session; simple HMAC or policy (including a trial policy)
        -- TPMT_SYM_DEF+: symmetric: the algorithm and key size for parameter encryption may select TPM_ALG_NULL
        -- TPMI_ALG_HASH: authHash: hash algorithm to use for the session Shall be a hash algorithm supported by the TPM and not TPM_ALG_NULL
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, tpm_key=0, bind=None, nonce_caller=None, encrypted_salt=None, session_type=None, symmetric=None, auth_hash=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.tpm_key = tpm_key
        self.bind = bind
        #self.authorization = authorization
        self.nonce_caller = nonce_caller
        self.encrypted_salt = encrypted_salt
        self.session_type = session_type
        self.symmetric = symmetric
        self.auth_hash = auth_hash
        if (self.DEBUG):
            print(" [i] TPM2_StartAuthSession OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_StartAuthSession: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        # Parse tpmKey
        self.tpm_key = hex(self.parse_uint32())

        # Parse bind
        self.bind = TpmiDhEntity(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.bind.parse()

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        # Parse nonceCaller
        self.nonce_caller = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.nonce_caller.parse()
        if self.nonce_caller.buf:
            self.nonce_caller.buf = "0x"+self.nonce_caller.buf.encode('hex')

        # Parse encryptedSalt
        self.encrypted_salt = Tpm2bEncryptedSecret(self.tpm_command, self.offset)
        self.offset = self.encrypted_salt.parse()

        # Parse sessionType
        self.session_type = TpmSe(self.tpm_command, self.offset)
        self.offset = self.session_type.parse()

        # Parse symmetric
        self.symmetric = TpmtSymDefObject(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.symmetric.parse()

        # Parse authHash
        self.auth_hash = TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=False)
        self.offset = self.auth_hash.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_StartAuthSession: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmStartAuthSessionResponse(TpmParser):
    """
    Page 40 Part 3 (TPM2_StartAuthSession Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize
        -- TPM_RC: responseCode

        -- TPMI_SH_AUTH_SESSION: sessionHandle: handle for the newly created session
        ========================================================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        -- TPM2B_NONCE (TPM2B_DIGEST): nonceTPM: the initial nonce from the TPM, used in the computation of the sessionKey
        #IF TPM_ST_SESSIONS: Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, session_handle='', nonce_tpm=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.session_handle = session_handle
        #self.parameter_size = parameter_size
        self.nonce_tpm = nonce_tpm
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_StartAuthSession Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_StartAuthSession Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        # Parse sessionHandle
        session_handle = self.parse_uint32()  # TODO: TRANSLATE and add HMAC options!!! to TPM_RS_PW
        if (session_handle == 0x40000009):
            self.session_handle = 'TPM_RS_PW'
        else:
            self.session_handle = hex(session_handle)


        if self.has_session: #case we have TPM_ST_SESSIONS
            # parse parameterSize
            self.parameter_size = self.parse_uint32()
        
        # Parse nonceTPM
        self.nonce_tpm = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.nonce_tpm.parse()
        if self.nonce_tpm.buf:
            self.nonce_tpm.buf = "0x"+self.nonce_tpm.buf.encode('hex')

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_StartAuthSessionR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmPcrRead(TpmParser):
    """ 
    Page 184 Part 3 (TPM2_PCR_Read) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS TPM_ST_SESSIONS if an audit session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_PCR_Read

        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
        -- TPML_PCR_SELECTION: pcrSelectionIn: The selection of PCR to read

    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, pcr_selection_in=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.authorization = authorization
        self.pcr_selection_in = pcr_selection_in
        if (self.DEBUG):
            print(" [i] TPM2_PCR_Read OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_PCR_Read: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        # Parse pcrSelectionIn
        self.pcr_selection_in = TpmlPcrSelection(self.tpm_command, self.offset)
        self.offset = self.pcr_selection_in.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_PCR_Read: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmPcrReadResponse(TpmParser):
    """
    Page 184 Part 3 (TPM2_PCR_Read Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        -- UINT32: pcrUpdateCounter: the current value of the PCR update counter
        -- TPML_PCR_SELECTION: pcrSelectionOut: the PCR in the returned list
        -- TPML_DIGEST: pcrValues: the contents of the PCR indicated in pcrSelectOut->pcrSelection[] as tagged digests
        #IF TPM_ST_SESSIONS: Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, pcr_update_counter=0, pcr_selection_out=None, pcr_values=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.parameter_size = parameter_size
        self.pcr_update_counter = pcr_update_counter
        self.pcr_selection_out = pcr_selection_out
        self.pcr_values = pcr_values
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_PCR_Read Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_PCR_Read Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            # parse parameterSize
            self.parameter_size = self.parse_uint32()

        # Parse pcrUpdateCounter
        self.pcr_update_counter = self.parse_uint32()

        # Parse pcrSelectionOut
        self.pcr_selection_out = TpmlPcrSelection(self.tpm_command, self.offset)
        self.offset = self.pcr_selection_out.parse()

        # Parse pcrValues
        self.pcr_values = TpmlDigest(self.tpm_command, self.offset)
        self.offset = self.pcr_values.parse()

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_PCR_ReadR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmPolicyPcr(TpmParser):
    """ 
    Page 82 Part 3 (TPM2_PolicyPCR) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS if an audit or decrypt session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_PolicyPCR
    
        -- TPMI_SH_POLICY: policySession: handle for the policy session being extended. Auth Index: None
            {POLICY_SESSION_FIRST: POLICY_SESSION_LAST}
        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
        -- TPM2B_DIGEST: pcrDigest: expected digest value of the selected PCR using the hash algorithm of the session; may be zero length
        -- TPML_PCR_SELECTION: pcrs: the PCR to include in the check digest
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, policy_session=0, pcr_digest=None, pcrs=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.policy_session = policy_session
        #self.authorization = authorization
        self.pcr_digest = pcr_digest
        self.pcrs = pcrs
        if (self.DEBUG):
            print(" [i] TPM2_PolicyPCR OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_PolicyPCR: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse policySession
        self.policy_session = hex(self.parse_uint32())


        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        # Parse pcrDigest
        self.pcr_digest = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.pcr_digest.parse()
        if self.pcr_digest.buf:
            self.pcr_digest.buf = "0x"+self.pcr_digest.buf.encode('hex')

        # Parse pcrs
        self.pcrs = TpmlPcrSelection(self.tpm_command, self.offset)
        self.offset = self.pcrs.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_PolicyPCR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmPolicyPcrResponse(TpmParser):
    """
    Page 82 Part 3 (TPM2_PolicyPCR Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ===========================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        #IF TPM_ST_SESSIONS: Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.parameter_size = parameter_size
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_PolicyPCR Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_PolicyPCR Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            # Parse parameterSize
            self.parameter_size = self.parse_uint32()

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_PolicyPCRR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmPolicyGetDigest(TpmParser):
    """ 
    Page 260 Part 3 (TPM2_PolicyGetDigest) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS if an audit or encrypt session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_PolicyGetDigest

        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
        -- TPMI_SH_POLICY: policySession: handle for the policy session. Auth Index: None
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, policy_session=0):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.authorization = authorization
        self.policy_session = policy_session
        if (self.DEBUG):
            print(" [i] TPM2_PolicyGetDigest OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_PolicyGetDigest: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        # Parse policy_session
        self.policy_session = hex(self.parse_uint32())

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_PolicyGetDigest: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmPolicyGetDigestResponse(TpmParser):
    """
    Page 260 Part 3 (TPM2_PolicyGetDigest Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        -- TPM2B_DIGEST: policyDigest: the current value of the policySession -> policyDigest
        #IF TPM_ST_SESSIONS: Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, policy_digest=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.parameter_size = parameter_size
        self.policy_digest = policy_digest
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_PolicyGetDigest Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_PolicyGetDigest Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            # Parse parameterSize
            self.parameter_size = self.parse_uint32()

        # Parse policyDigest
        self.policy_digest = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.policy_digest.parse()
        if self.policy_digest.buf:
            self.policy_digest.buf = "0x"+self.policy_digest.buf.encode('hex')

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_PolicyGetDigestR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEvictControl(TpmParser):
    """ 
    Page 329 Part 3 (TPM2_EvictControl)
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_EvictControl {NV}
        
        -- TPMI_RH_PROVISION (TPM_RH_OWNER or TPM_RH_PLATFORM): @auth: TPM_RH_OWNER or TPM_RH_PLATFORM+{PP} Auth Handle: 1 Auth Role: USER
        -- TPMI_DH_OBJECT: objectHandle: the handle of a loaded object. Auth Index: None
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        ========================================================================
        -- TPMI_DH_PERSISTENT: persistentHandle: if objectHandle is a transient object handle, then this is the persistent handle for the object. if objectHandle is a persistent object handle, then it shall be the same value as persistentHandle
            Allowed Values (Page 78 part 2)
            {PERSISTENT_FIRST:PERSISTENT_LAST} 
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, auth='', object_handle=0, authorization=None, persistent_handle=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.auth = auth
        self.object_handle = object_handle
        self.authorization = authorization
        self.persistent_handle = persistent_handle
        if (self.DEBUG):
            print(" [i] TPM2_EvictControl OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_EvictControl: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse auth
        auth = self.parse_uint32()
        if auth == 0x40000001:
            self.auth = 'TPM_RH_OWNER'
        elif auth == 0x4000000C:
            self.auth = 'TPM_RH_PLATFORM'
        else:
            self.auth = hex(auth)

        # Parse objectHandle
        self.object_handle = hex(self.parse_uint32())

        # Parse authorization
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse persistentHandle
        self.persistent_handle = hex(self.parse_uint32())

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_EvictControl: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEvictControlResponse(TpmParser):
    """
    Page 329 Part 3 (TPM2_EvictControl Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- # Parameter area size UINT32
        -- # Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_EvictControl Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_EvictControl Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_EvictControlR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmUnseal(TpmParser):
    """ 
    Page 67 Part 3 (TPM2_Unseal)
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_Unseal
        
        -- TPMI_DH_OBJECT: @itemHandle: handle of a loaded data object. Auth Index: 1. Auth Role: USER
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        ========================================================================
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, item_handle=0, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.item_handle = item_handle
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_Unseal OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Unseal: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse itemHandle
        self.item_handle = hex(self.parse_uint32())

        # Parse authorization
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_Unseal: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmUnsealResponse(TpmParser):
    """
    Page 67 Part 3 (TPM2_Unseal Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- #Parameter area size UINT32
        -- TPM2B_SENSITIVE_DATA: outData: unsealed data. Size of outData is limited to be no more than 128 octets.
        -- # Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, out_data=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.out_data = out_data
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_Unseal Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Unseal Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse outData
        self.out_data = Tpm2bSensitiveData(self.tpm_command, self.offset)
        self.offset = self.out_data.parse()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_UnsealR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset


class TpmFlushContext(TpmParser):
    """
    Page 325 Part 3 (TPM2_FlushContext) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_NO_SESSIONS
        -- UINT32 commandSize:
        -- TPM_CC: commandCode: TPM_CC_ContextLoad
        
        ===========================================================
        -- TPMI_DH_CONTEXT: flushHandle: the handle of the item to flush. NOTE This is a use of a handle as a parameter.
            Possible Values Page 80  Part 2
            {HMAC_SESSION_FIRST : HMAC_SESSION_LAST}
            {POLICY_SESSION_FIRST:POLICY_SESSION_LAST}
            {TRANSIENT_FIRST:TRANSIENT_LAST}
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, flush_context=0):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.flush_context = flush_context

        if (self.DEBUG):
            print(" [i] TPM2_FlushContext OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_FlushContext: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.flush_context = hex(self.parse_uint32())

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_FlushContext: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmFlushContextResponse(TpmParser):
    """
    Page 325 Part 3 (TPM2_FlushContext Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        if (self.DEBUG):
            print(" [i] TPM2_FlushContext Response OFFSET:{}".format(self.offset)) #!debug

    def __str__(self):
        return '[i] TPM2_FlushContext Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))

    def parse(self):
        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_FlushContextR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmPcrExtend(TpmParser):
    """ 
    Page 178 Part 3 (TPM2_PCR_Extend)
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_PCR_Extend {NV}
        
        -- TPMI_DH_PCR+: @pcrHandle: handle of the PCR. Auth Handle: 1. Auth Role: USER
                Allowed Values (Page 79 Part 2)
                {PCR_FIRST:PCR_LAST}
                +TPM_RH_NULL
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_PCR)
        ========================================================================
        -- TPML_DIGEST_VALUES: digests: list of tagged digest values to be extended
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, pcr_handle=0, authorization=None, digests=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.pcr_handle = pcr_handle
        self.authorization = authorization
        self.digests = digests
        if (self.DEBUG):
            print(" [i] TPM2_PCR_Extend OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_PCR_Extend: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        # Parse pcrHandle
        self.pcr_handle = hex(self.parse_uint32())

        # Parse authorization
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse digests
        self.digests = TpmlDigestValues(self.tpm_command, self.offset)
        self.offset = self.digests.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_PCR_Extend: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmPcrExtendResponse(TpmParser):
    """
    Page 178 Part 3 (TPM2_PCR_Extend Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- # Parameter area size UINT32
        -- # Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_PCR_Extend Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_PCR_Extend Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_PCR_ExtendR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmGetRandom(TpmParser):
    """ 
    Page 119 Part 3 (TPM2_GetRandom) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS if an audit or encrypt session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_GetRandom

        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
        -- UINT16: bytesRequested: number of octets to return
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, bytes_requested=0):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.authorization = authorization
        self.bytes_requested = bytes_requested
        if (self.DEBUG):
            print(" [i] TPM2_GetRandom OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_GetRandom: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        # Parse bytesRequested
        self.bytes_requested = self.parse_uint16()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_GetRandom: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmGetRandomResponse(TpmParser):
    """
    Page 119 Part 3 (TPM2_GetRandom Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        -- TPM2B_DIGEST: randomBytes: the random octets
        #IF TPM_ST_SESSIONS: Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, random_bytes=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.parameter_size = parameter_size
        self.random_bytes = random_bytes
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_GetRandom Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_GetRandom Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            # Parse parameterSize
            self.parameter_size = self.parse_uint32()

        # Parse randomBytes
        self.random_bytes = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.random_bytes.parse()
        if self.random_bytes.buf:
            self.random_bytes.buf = "0x"+self.random_bytes.buf.encode('hex')

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_GetRandomR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset


class TpmHash(TpmParser):
    """ 
    Page 113 Part 3 (TPM2_Hash) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS if an audit, decrypt, or encrypt session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_Hash

        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
        -- TPM2B_MAX_BUFFER: data: data to be hashed
        -- TPMI_ALG_HASH: hashAlg: algorithm for the hash being computed - shall not be TPM_ALG_NULL
        -- TPMI_RH_HIERARCHY+: hierarchy: hierarchy to use for the ticket (TPM_RH_NULL allowed)
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, data=None, hash_alg=0, hierarchy=0 ):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.authorization = authorization
        self.data = data
        self.hash_alg = hash_alg
        self.hierarchy = hierarchy
        if (self.DEBUG):
            print(" [i] TPM2_Hash OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Hash: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        # Parse data
        self.data = Tpm2bMaxBuffer(self.tpm_command, self.offset)
        self.offset = self.data.parse()

        # Parse hash_alg
        self.hash_alg = TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=False)
        self.offset = self.hash_alg.parse()

        # Parse hierarchy
        self.hierarchy = TpmiRhHierarchy(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.hierarchy.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_Hash: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmHashResponse(TpmParser):
    """
    Page 113 Part 3 (TPM2_Hash Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        -- TPM2B_DIGEST: outHash: results
        -- TPMT_TK_HASHCHECK: validation: ticket indicating that the sequence of octets used to compute outDigest did not start with TPM_GENERATED_VALUE...
        #IF TPM_ST_SESSIONS: Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, out_hash=None, validation=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.parameter_size = parameter_size
        self.out_hash = out_hash
        self.validation = validation
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_Hash Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Hash Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            # Parse parameterSize
            self.parameter_size = self.parse_uint32()

        # Parse outHash
        self.out_hash = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.out_hash.parse()
        if self.out_hash.buf:
            self.out_hash.buf = "0x"+self.out_hash.buf.encode('hex')

        # Parse validation
        self.validation = TpmtTkHashcheck(self.tpm_command, self.offset)
        self.offset = self.validation.parse()

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_HashR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset


class TpmCommit(TpmParser):
    """
    Page 161 Part 3 (TPM2_Commit) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_Commit
        
        -- TPMI_DH_OBJECT: @signHandle: handle of the key that will be used in the signing operation. Auth Index:: 1 Auth Role:: USER
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        ========================================================================
        -- TPM2B_ECC_POINT: P1: a point ( M ) on the curve used by signHandle
        -- TPM2B_SENSITIVE_DATA: s2: octet array used to derive x-coordinate of a base point
        -- TPM2B_ECC_PARAMETER: y2: y coordinate of the point associated with s2
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, sign_handle=0, authorization=None, p1=None, s2=None, y2=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.sign_handle = sign_handle
        self.authorization = authorization
        self.p1 = p1
        self.s2 = s2
        self.y2 = y2
        if (self.DEBUG):
            print(" [i] TPM2_Commit OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Commit: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse signHandle
        self.sign_handle = hex(self.parse_uint32())

        # Parse Authorization_structure
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse P1
        self.p1 = Tpm2bEccPoint(self.tpm_command, self.offset)
        self.offset = self.p1.parse()

        # Parse s2
        self.s2 = Tpm2bSensitiveData(self.tpm_command, self.offset)
        self.offset = self.s2.parse()

        # Parse y2
        self.y2 = Tpm2bEccParameter(self.tpm_command, self.offset)
        self.offset = self.y2.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_Commit: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmCommitResponse(TpmParser):
    """
    Page 161 Part 3 (TPM2_Commit Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #Parameter area size UINT32
        -- TPM2B_ECC_POINT: K: ECC point K = [ds](x2,y2)
        -- TPM2B_ECC_POINT: L: ECC point L = [r](x2,y2)
        -- TPM2B_ECC_POINT: E: ECC point E = [r]P1
        -- UINT16: counter: least-significant 16 bits of commitCount
        # Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, k=None, l=None, e=None, counter=0, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.k = k
        self.l = l
        self.e = e
        self.counter = counter
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_Commit Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Commit Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse K
        self.k = Tpm2bEccPoint(self.tpm_command, self.offset)
        self.offset = self.k.parse()

        # Parse L
        self.l = Tpm2bEccPoint(self.tpm_command, self.offset)
        self.offset = self.l.parse()

        # Parse E
        self.e = Tpm2bEccPoint(self.tpm_command, self.offset)
        self.offset = self.e.parse()

        # Parse counter
        self.counter = self.parse_uint16()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_CommitR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmSign(TpmParser):
    """ 
    Page 170 Part 3 (TPM2_Sign)
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_Sign
        
        -- TPMI_DH_OBJECT: @keyHandle: Handle of key that will perform signing. Auth Handle: 1. Auth Role: USER
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        ========================================================================
        -- TPM2B_DIGEST: digest: digest to be signed
        -- TPMT_SIG_SCHEME+: inScheme: signing scheme to use if the scheme for keyHandle is TPM_ALG_NULL
        -- TPMT_TK_HASHCHECK: validation: proof that digest was created by the TPM...
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, key_handle=0, authorization=None, digest=None, in_scheme=None, validation=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.key_handle = key_handle
        self.authorization = authorization
        self.digest = digest
        self.in_scheme = in_scheme
        self.validation = validation
        if (self.DEBUG):
            print(" [i] TPM2_Sign OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Sign: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        # Parse keyHandle
        self.key_handle = hex(self.parse_uint32())

        # Parse authorization
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse digest
        self.digest = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.digest.parse()
        if self.digest.buf:
            self.digest.buf = "0x"+self.digest.buf.encode('hex')

        # Parse inScheme
        self.in_scheme = TpmtSigScheme(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.in_scheme.parse()

        # Parse validation
        self.validation = TpmtTkHashcheck(self.tpm_command, self.offset)
        self.offset = self.validation.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_Sign: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmSignResponse(TpmParser):
    """
    Page 170 Part 3 (TPM2_Sign Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- # Parameter area size UINT32
        -- TPMT_SIGNATURE: signature: the signature
        -- # Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, signature=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.signature = signature
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_Sign Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Sign Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse signature
        self.signature = TpmtSignature(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.signature.parse()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_SignR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmMakeCredential(TpmParser):
    """ 
    Page 64 Part 3 (TPM2_MakeCredential)
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS if an audit, encrypt, or decrypt session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_MakeCredential
        
        -- TPMI_DH_OBJECT: handle: loaded public area, used to encrypt the sensitive area containing the credential key. Auth Index: None
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
        -- TPM2B_DIGEST: credential: the credential information
        -- TPM2B_NAME: objectName: Name of the object to which the credential applies
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, handle=0, credential=None, object_name=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.handle = handle
        # self.authorization = authorization
        self.credential = credential
        self.object_name = object_name
        if (self.DEBUG):
            print(" [i] TPM2_MakeCredential OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_MakeCredential: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        # Parse handle
        self.handle = hex(self.parse_uint32())

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        # Parse credential
        self.credential = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.credential.parse()

        # Parse objectName
        self.object_name = Tpm2bName(self.tpm_command, self.offset)
        self.offset = self.object_name.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_MakeCredential: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmMakeCredentialResponse(TpmParser):
    """
    Page 64 Part 3 (TPM2_MakeCredential Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        -- TPM2B_ID_OBJECT: credentialBlob: the credential
        -- TPM2B_ENCRYPTED_SECRET: secret: handle algorithm-dependent data that wraps the key that encrypts credentialBlob
        #IF TPM_ST_SESSIONS: Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, credential_blob=None, secret=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        # self.parameter_size = parameter_size
        self.credential_blob = credential_blob
        self.secret = secret
        # self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_MakeCredential Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_MakeCredential Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            # Parse parameterSize
            self.parameter_size = self.parse_uint32()

        # Parse credentialBlob 
        self.credential_blob = Tpm2bIdObject(self.tpm_command, self.offset)
        self.offset = self.credential_blob.parse()

        # Parse secret
        self.secret = Tpm2bEncryptedSecret(self.tpm_command, self.offset)
        self.offset = self.secret.parse()
        
        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_MakeCredentialR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmActivateCredential(TpmParser):
    """ 
    Page 61 Part 3 (TPM2_ActivateCredential)
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_ActivateCredential
        
        -- TPMI_DH_OBJECT: @activateHandle: Handle of the object associated with certificate in credentialBlob. Auth Handle: 1. Auth Role: ADMIN
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        -- TPMI_DH_OBJECT: @keyHandle: loaded key used to decrypt the TPMS_SENSITIVE in credentialBlob. Auth Index 2: Auth Role: USER
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        ========================================================================
        -- TPM2B_ID_OBJECT: credentialBlob: the credential
        -- TPM2B_ENCRYPTED_SECRET: secret: keyHandle algorithm-dependent encrypted seed that protects credentialBlob 
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, activate_handle=0, key_handle=0, authorization=None, credential_blob=None, secret=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.activate_handle = activate_handle
        self.key_handle = key_handle
        self.authorization = authorization
        self.credential_blob = credential_blob
        self.secret = secret
        if (self.DEBUG):
            print(" [i] TPM2_ActivateCredential OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ActivateCredential: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        # Parse activateHandle
        self.activate_handle = hex(self.parse_uint32())

        # Parse keyHandle
        self.key_handle = hex(self.parse_uint32())

        # Parse authorization
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse credentialBlob
        self.credential_blob = Tpm2bIdObject(self.tpm_command, self.offset)
        self.offset = self.credential_blob.parse()

        # Parse secret
        self.secret = Tpm2bEncryptedSecret(self.tpm_command, self.offset)
        self.offset = self.secret.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ActivateCredential: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmActivateCredentialResponse(TpmParser):
    """
    Page 61 Part 3 (TPM2_ActivateCredential Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- # Parameter area size UINT32
        -- TPM2B_DIGEST: certInfo: the decrypted certificate information...
        -- # Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, cert_info=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.cert_info = cert_info
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_ActivateCredential Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ActivateCredential Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse certInfo
        self.cert_info = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.cert_info.parse()
        if self.cert_info.buf:
            self.cert_info.buf = "0x"+self.cert_info.buf.encode('hex')

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ActivateCredentialR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmPolicySecret(TpmParser):
    """
    Page 214 Part 3 (TPM2_PolicySecret) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32: commandSize: 
        -- TPM_CC: commandCode: TPM_CC_PolicySecret
        
        -- TPMI_DH_ENTITY: @authHandle: handle for an entity providing the authorization.    Auth Index:: 1 Auth Role:: USER
        -- TPMI_SH_POLICY: policySession: handle for the policy session being extended. Auth Index: None
            Accepted values: Page 80 Part 2
            {POLICY_SESSION_FIRST: POLICY_SESSION_LAST}: range of policy authorization session handles
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_SH_POLICY)
        ========================================================================
        -- TPM2B_NONCE (TPM2B_DIGEST): nonceTPM: the policy nonce for the session. This can be the Empty Buffer.
        -- TPM2B_DIGEST: cpHashA: digest of the command parameters to which this authorization is limited...
        -- TPM2B_NONCE (TPM2B_DIGEST: policyRef: a reference to a policy relating to the authorization - may be the Empty Buffer...
        -- INT32: expiration: time when authorization will expire, measured in seconds from the time that nonceTPM was generated...
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, auth_handle=None, policy_session=0, authorization=None, nonce_tpm=None, cp_hash_a=None, policy_ref=None, expiration=0):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.auth_handle = auth_handle
        self.policy_session = policy_session
        self.authorization = authorization
        self.nonce_tpm = nonce_tpm
        self.cp_hash_a = cp_hash_a
        self.policy_ref = policy_ref
        self.expiration = expiration
        if (self.DEBUG):
            print(" [i] TPM2_PolicySecret OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_PolicySecret: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse @authHandle
        self.auth_handle = TpmiDhEntity(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.auth_handle.parse()

        # Parse policySession
        self.policy_session = hex(self.parse_uint32())

        # Parse Authorization_structure
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse nonceTPM
        self.nonce_tpm = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.nonce_tpm.parse()
        if self.nonce_tpm.buf:
            self.nonce_tpm.buf = "0x"+self.nonce_tpm.buf.encode('hex')

        # Parse cpHashA
        self.cp_hash_a = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.cp_hash_a.parse()
        if self.cp_hash_a.buf:
            self.cp_hash_a.buf = "0x"+self.cp_hash_a.buf.encode('hex')

        # Parse policyRef
        self.policy_ref = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.policy_ref.parse()
        if self.policy_ref.buf:
            self.policy_ref.buf = "0x"+self.policy_ref.buf.encode('hex')

        # Parse expiration
        self.expiration = self.parse_uint32()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_PolicySecret: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmPolicySecretResponse(TpmParser):
    """
    Page 214 Part 3 (TPM2_PolicySecret Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #Parameter area size UINT32
        -- TPM2B_TIMEOUT (TPM2B_DIGEST): timeout: implementation-specific time value used to indicate to the TPM when the ticket expires; this ticket will use the TPMT_ST_AUTH_SECRET structure tag
        -- TPMT_TK_AUTH: policyTicket: produced if the command succeeds and expiration in the command was non-zero
        # Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, timeout=None, policy_ticket=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.timeout = timeout
        self.policy_ticket = policy_ticket
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_PolicySecret Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_PolicySecret Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse timeout
        self.timeout = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.timeout.parse()
        if self.timeout.buf:
            self.timeout.buf = "0x"+self.timeout.buf.encode('hex')

        # Parse policyTicket
        self.policy_ticket = TpmtTkAuth(self.tpm_command, self.offset)
        self.offset = self.policy_ticket.parse()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_PolicySecretR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmCertify(TpmParser):
    """ 
    Page 142 Part 3 (TPM2_Certify)
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_Certify
        
        -- TPMI_DH_OBJECT: @objectHandle: handle of the object to be certified. Auth Handle: 1. Auth Role: ADMIN
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        -- TPMI_DH_OBJECT+: @signHandle: handle of the key used to sign the attestation structure. Auth Index 2: Auth Role: USER
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT+)
        ========================================================================
        -- TPM2B_DATA: qualifyingData: user provided qualifying data
        -- TPMT_SIG_SCHEME+: inScheme: signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, object_handle=0, sign_handle=0, authorization=None, qualifying_data=None, in_scheme=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.object_handle = object_handle
        self.sign_handle = sign_handle
        self.authorization = authorization
        self.qualifying_data = qualifying_data
        self.in_scheme = in_scheme
        if (self.DEBUG):
            print(" [i] TPM2_Certify OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Certify: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        # Parse @objectHandle
        self.object_handle = hex(self.parse_uint32())

        # Parse @signHandle
        self.sign_handle = hex(self.parse_uint32())

        # Parse authorization
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse qualifyingData
        self.qualifying_data = Tpm2bData(self.tpm_command, self.offset)
        self.offset = self.qualifying_data.parse()

        # Parse inScheme
        self.in_scheme = TpmtSigScheme(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.in_scheme.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_Certify: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmCertifyResponse(TpmParser):
    """
    Page 142 Part 3 (TPM2_Certify Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- # Parameter area size UINT32
        -- TPM2B_ATTEST: certifyInfo: the structure that was signed
        -- TPMT_SIGNATURE: signature: the asymmetric signature over certifyInfo using the key referenced by signHandle 
        -- # Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, certify_info=None, signature=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.certify_info = certify_info
        self.signature = signature
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_Certify Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_Certify Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse certifyInfo
        self.certify_info = Tpm2bAttest(self.tpm_command, self.offset)
        self.offset = self.certify_info.parse()

        # Parse signature
        self.signature = TpmtSignature(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.signature.parse()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_CertifyR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmVerifySignature(TpmParser):
    """ 
    Page 167 Part 3 (TPM2_VerifySignature) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS if an audit or encrypt session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_VerifySignature
    
        -- TPMI_DH_OBJECT: keyHandle: handle of public key that will be used in the validation. Auth Index: None
        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
        -- TPM2B_DIGEST: digest: digest of the signed message
        -- TPMT_SIGNATURE: signature: signature to be tested
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, key_handle=0, digest=None, signature=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.key_handle = key_handle
        #self.authorization = authorization
        self.digest = digest
        self.signature = signature
        if (self.DEBUG):
            print(" [i] TPM2_VerifySignature OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_VerifySignature: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse keyHandle
        self.key_handle = hex(self.parse_uint32())

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        # Parse digest
        self.digest = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.digest.parse()
        if self.digest.buf:
            self.digest.buf = "0x"+self.digest.buf.encode('hex')

        # Parse signature
        self.signature = TpmtSignature(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.signature.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_VerifySignature: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmVerifySignatureResponse(TpmParser):
    """
    Page 167 Part 3 (TPM2_VerifySignature Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ===========================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        -- TPMT_TK_VERIFIED: validation
        #IF TPM_ST_SESSIONS: Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, validation=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.parameter_size = parameter_size
        self.validation = validation
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_VerifySignature Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_VerifySignature Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            # Parse parameterSize
            self.parameter_size = self.parse_uint32()

        # Parse validation
        self.validation = TpmtTkVerified(self.tpm_command, self.offset)
        self.offset = self.validation.parse()

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_VerifySignatureR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEcdhKeygen(TpmParser):
    """ 
    Page 93 Part 3 (TPM2_ECDH_KeyGen) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS if an audit or encrypt session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_ECDH_KeyGen
        
        -- TPMI_DH_OBJECT: keyHandle: Handle of a loaded ECC key public area. Auth Index: None
            Allowed Values (Page 77 Part 2)
            {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
            {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, key_handle=0):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.key_handle = key_handle
        # self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_ECDH_KeyGen OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ECDH_KeyGen: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse keyHandle
        self.key_handle = hex(self.parse_uint32())

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ECDH_KeyGen: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEcdhKeygenResponse(TpmParser):
    """
    Page 93 Part 3 (TPM2_ECDH_KeyGen Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        -- TPM2B_ECC_POINT: zPoint: results of P:=h[de]Qs
        -- TPM2B_ECC_POINT: pubPoint: generated ephemeral public point (Qe)
        #IF TPM_ST_SESSIONS: Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, z_point=None, pub_point=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.parameter_size = parameter_size
        self.z_point = z_point
        self.pub_point = pub_point
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_ECDH_KeyGen Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ECDH_KeyGen Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            # Parse parameterSize
            self.parameter_size = self.parse_uint32()

        # Parse zPoint
        self.z_point = Tpm2bEccPoint(self.tpm_command, self.offset)
        self.offset = self.z_point.parse()

        # Parse pubPoint
        self.pub_point = Tpm2bEccPoint(self.tpm_command, self.offset)
        self.offset = self.pub_point.parse()

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ECDH_KeyGenR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEcdhZgen(TpmParser):
    """ 
    Page 96 Part 3 (TPM2_ECDH_ZGen)
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_ECDH_ZGen
        
        -- TPMI_DH_OBJECT: @keyHandle: handle of a loaded ECC key. Auth Handle: 1. Auth Role: USER
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        ========================================================================
        -- TPM2B_ECC_POINT: inPoint: a public key
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, key_handle=0, authorization=None, in_point=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.key_handle = key_handle
        self.authorization = authorization
        self.in_point = in_point
        if (self.DEBUG):
            print(" [i] TPM2_ECDH_ZGen OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ECDH_ZGen: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        # Parse @keyHandle
        self.key_handle = hex(self.parse_uint32())

        # Parse authorization
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse inPoint
        self.in_point = Tpm2bEccPoint(self.tpm_command, self.offset)
        self.offset = self.in_point.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ECDH_ZGen: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEcdhZgenResponse(TpmParser):
    """
    Page 96 Part 3 (TPM2_ECDH_ZGen Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- # Parameter area size UINT32
        -- TPM2B_ECC_POINT: outPoint: X and Y coordinates of the product of the multiplication Z=(xz,yz):=[hds]Q8
        -- # Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, out_point=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.out_point = out_point
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_ECDH_ZGen Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ECDH_ZGen Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse certifyInfo
        self.out_point = Tpm2bEccPoint(self.tpm_command, self.offset)
        self.offset = self.out_point.parse()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ECDH_ZGenR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEccParameters(TpmParser):
    """ 
    Page 99 Part 3 (TPM2_ECC_Parameters) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS if an audit session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_ECC_Parameters
        
        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
        -- TPMI_ECC_CURVE ($ECC_CURVES): curveID: parameter set selector
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, curve_id=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        # self.authorization = authorization
        self.curve_id = curve_id
        if (self.DEBUG):
            print(" [i] TPM2_ECC_Parameters OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ECC_Parameters: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        # Parse curveID
        self.curve_id = TpmEccCurve(self.tpm_command, self.offset)  # TODO: not sure about this
        self.offset = self.curve_id.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ECC_Parameters: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEccParametersResponse(TpmParser):
    """
    Page 99 Part 3 (TPM2_ECC_Parameters Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        -- TPMS_ALGORITHM_DETAIL_ECC: parameters: ECC parameters for the selected curve
        #IF TPM_ST_SESSIONS: Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, parameters=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.parameter_size = parameter_size
        self.parameters = parameters
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_ECC_Parameters Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ECC_Parameters Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            # Parse parameterSize
            self.parameter_size = self.parse_uint32()

        # Parse parameters
        self.parameters = TpmsAlgorithmDetailEcc(self.tpm_command, self.offset)
        self.offset = self.parameters.parse()

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ECC_ParametersR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEcEphemeral(TpmParser):
    """ 
    Page 164 Part 3 (TPM2_EC_Ephemeral) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS if an audit or encrypt session is present; otherwise, TPM_ST_NO_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_EC_Ephemeral
        
        # IF TPM_ST_SESSIONS: Authorization structure
        ========================================================================
        -- TPMI_ECC_CURVE ($ECC_CURVES): curveID: The curve for the computed ephemeral point
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, curve_id=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        # self.authorization = authorization
        self.curve_id = curve_id
        if (self.DEBUG):
            print(" [i] TPM2_EC_Ephemeral OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_EC_Ephemeral: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
            self.offset = self.authorization.parse()
            self.session_count = len(self.authorization.authorization_structures)

        # Parse curveID
        self.curve_id = TpmEccCurve(self.tpm_command, self.offset)  # TODO: not sure about this
        self.offset = self.curve_id.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_EC_Ephemeral: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmEcEphemeralResponse(TpmParser):
    """
    Page 164 Part 3 (TPM2_EC_Ephemeral Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        #IF TPM_ST_SESSIONS: Parameter area size UINT32. 
        -- TPM2B_ECC_POINT: Q: ephemeral public key Q:=[r]G
        -- UINT16: counter: least-significant 16 bits of commitCount
        #IF TPM_ST_SESSIONS: Authorization Area 
    """

    def __init__(self, tpm_command='', offset=0, has_session=False, session_count=0, q=None, counter=0):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        #self.parameter_size = parameter_size
        self.q = q
        self.counter = counter
        #self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_EC_Ephemeral Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_EC_Ephemeral Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.has_session: #case we have TPM_ST_SESSIONS
            # Parse parameterSize
            self.parameter_size = self.parse_uint32()

        # Parse Q
        self.q = Tpm2bEccPoint(self.tpm_command, self.offset)
        self.offset = self.q.parse()

        # Parse counter
        self.counter = self.parse_uint16()

        if self.has_session: #case we have TPM_ST_SESSIONS
            self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
            self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_EC_EphemeralR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmZgen2Phase(TpmParser):
    """ 
    Page 102 Part 3 (TPM2_ZGen_2Phase) Command
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_ZGen_2Phase
        
        -- TPMI_DH_OBJECT: @keyA: handle of an unrestricted decryption key ECC. The private key referenced by this handle is used as ds,A. Auth Index: 1 Auth Role: USER
                Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        ========================================================================
        -- TPM2B_ECC_POINT: inQsB: other party's static public key (Qs,B=(Xs,B, Ys,B))
        -- TPM2B_ECC_POINT: inQeB: other party's ephemeral public key (Qe,B=(Xe,B, Ye,B))
        -- TPMI_ECC_KEY_EXCHANGE: inScheme: the key exchange scheme
        -- UINT16: counter: value returned by TPM2_EC_Ephemeral()
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, key_a=0, authorization=None, in_qs_b=None, in_qe_b=None, in_scheme=None, counter=0):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.key_a = key_a
        self.authorization = authorization
        self.in_qs_b = in_qs_b
        self.in_qe_b = in_qe_b
        self.in_scheme = in_scheme
        self.counter = counter
        if (self.DEBUG):
            print(" [i] TPM2_ZGen_2Phase OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ZGen_2Phase: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse keyA
        self.key_a = hex(self.parse_uint32())

        # Parse authorization
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse inQsB
        self.in_qs_b = Tpm2bEccPoint(self.tpm_command, self.offset)
        self.offset = self.in_qs_b.parse()

        # Parse inQeB
        self.in_qe_b = Tpm2bEccPoint(self.tpm_command, self.offset)
        self.offset = self.in_qe_b.parse()


        # Parse inScheme
        self.in_scheme = TpmiEccKeyExchange(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.in_scheme.parse()

        # Parse counter
        self.counter = self.parse_uint16()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ZGen_2Phase: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmZgen2PhaseResponse(TpmParser):
    """
    Page 102 Part 3 (TPM2_ZGen_2Phase Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- #Parameter area size UINT32
        -- TPM2B_ECC_POINT: outZ1: X and Y coordinates of the computed value (scheme dependent)
        -- TPM2B_ECC_POINT: outZ2: X and Y coordinates of the second computed value (scheme dependent)
        -- # Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, out_z1=None, out_z2=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.out_z1 = out_z1
        self.out_z2 = out_z2
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_ZGen_2Phase Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_ZGen_2Phase Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse outZ1
        self.out_z1 = Tpm2bEccPoint(self.tpm_command, self.offset)
        self.offset = self.out_z1.parse()

        # Parse outZ2
        self.out_z2 = Tpm2bEccPoint(self.tpm_command, self.offset)
        self.offset = self.out_z2.parse()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_ZGen_2PhaseR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmCertifyCreation(TpmParser):
    """ 
    Page 145 Part 3 (TPM2_CertifyCreation)
        -- TPMI_ST_COMMAND_TAG: tag: TPM_ST_SESSIONS
        -- UINT32 commandSize: 
        -- TPM_CC: commandCode: TPM_CC_CertifyCreation
        
        -- TPMI_DH_OBJECT+: @signHandle: handle of the key that will sign the attestation block. Auth Handle: 1. Auth Role:: USER
               Allowed Values (Page 77 Part 2)
                {TRANSIENT_FIRST:TRANSIENT_LAST}: allowed range for transient objects
                {PERSISTENT_FIRST:PERSISTENT_LAST}: allowed range for persistent objects
                +TPM_RH_NULL: the conditional value
        -- TPMI_DH_OBJECT: objectHandle: the object associated with the creation data. Auth Index: None
        -- Since the handle has a '@' prepended, we have Authorization Structure after TPMI_DH_OBJECT)
        ========================================================================
        -- TPM2B_DATA: qualifyingData: user-provided qualifying data
        -- TPM2B_DIGEST: creationHash: hash of the creation data produced by TPM2_Create() or TPM2_CreatePrimary()
        -- TPMT_SIG_SCHEME+: inScheme: signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        -- TPMT_TK_CREATION: creationTicket: ticket produced by TPM2_Create() or TPM2_CreatePrimary()
    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, sign_handle=0, object_handle=0, authorization=None, qualifying_data=None, creation_hash=None, in_scheme=None, creation_ticket=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.sign_handle = sign_handle
        self.object_handle = object_handle
        self.authorization = authorization
        self.qualifying_data = qualifying_data
        self.creation_hash = creation_hash
        self.in_scheme = in_scheme
        self.creation_ticket = creation_ticket
        if (self.DEBUG):
            print(" [i] TPM2_CertifyCreation OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_CertifyCreation: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse @signHandle
        self.sign_handle = hex(self.parse_uint32())

        # Parse objectHandle
        self.object_handle = hex(self.parse_uint32())

        # Parse authorization
        self.authorization = AuthorizationAreaC(self.tpm_command,self.offset)
        self.offset = self.authorization.parse()
        self.session_count = len(self.authorization.authorization_structures)

        # Parse qualifyingData
        self.qualifying_data = Tpm2bData(self.tpm_command, self.offset)
        self.offset = self.qualifying_data.parse()

        # Parse creationHash
        self.creation_hash = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.creation_hash.parse()
        if self.creation_hash.buf:
            self.creation_hash.buf = "0x"+self.creation_hash.buf.encode('hex')

        # Parse inScheme
        self.in_scheme = TpmtSigScheme(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.in_scheme.parse()

        # Parse creationTicket
        self.creation_ticket = TpmtTkCreation(self.tpm_command, self.offset)
        self.offset = self.creation_ticket.parse()

        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_CertifyCreation: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset



class TpmCertifyCreationResponse(TpmParser):
    """
    Page 145 Part 3 (TPM2_CertifyCreation Response)
        -- TPM_ST: tag: see clause 6
        -- UINT32: responseSize:
        -- TPM_RC: responseCode

        ========================================================================
        -- # Parameter area size UINT32
        -- TPM2B_ATTEST: certifyInfo: the structure that was signed
        -- TPMT_SIGNATURE: signature: the signature over certifyInfo
        -- # Authorization Area 

    """

    def __init__(self, tpm_command='', offset=0, has_session=True, session_count=0, parameter_size=0, certify_info=None, signature=None, authorization=None):
        TpmParser.__init__(self, tpm_command, offset, has_session, session_count)
        self.parameter_size = parameter_size
        self.certify_info = certify_info
        self.signature = signature
        self.authorization = authorization
        if (self.DEBUG):
            print(" [i] TPM2_CertifyCreation Response OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2_CertifyCreation Response: \n'+'\n'.join(
            ('\t{} = {}'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse parameterSize
        self.parameter_size = self.parse_uint32()

        # Parse certifyInfo
        self.certify_info = Tpm2bAttest(self.tpm_command, self.offset)
        self.offset = self.certify_info.parse()

        # Parse signature
        self.signature = TpmtSignature(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.signature.parse()

        # Parse authorization
        self.authorization = AuthorizationAreaR(self.tpm_command, self.offset, self.session_count)
        self.offset = self.authorization.parse()


        if (self.DEBUG):
            print(" [D] CURRENT OFFSET TPM2_CertifyCreationR: {} of size {}".format(self.offset,len(self.tpm_command))) #!debug
        return self.offset
        
#------------------------------------------- END OF COMMANDS -------------------------------------------------

class TpmiEccKeyExchange(TpmParser):
    """
    Page 86 Part 2 #TODO: Not sure about this
    Definition of (TPM_ALG_ID){ECC} TPMI_ECC_KEY_EXCHANGE Type
    Values: Comments
        -- TPM_ALG_!ALG.AM: any ECC key exchange method
        -- TPM_ALG_SM2: SM2 is typed as signing but may be used as a key-exchange protocol
        -- +TPM_ALG_NULL
    """

    def __init__(self, tpm_command, offset, optional_value, tpmi_ecc_key_exchange=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.optional_value = optional_value
        self.tpmi_ecc_key_exchange = tpmi_ecc_key_exchange
        if (self.DEBUG):
            print(" [i] TPMI_ECC_KEY_EXCHANGE OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMI_ECC_KEY_EXCHANGE:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        tpmi_ecc_key_exchange = self.parse_uint16()

        if tpmi_ecc_key_exchange in TpmAlg.tpm_alg_assymetric and tpmi_ecc_key_exchange in TpmAlg.tpm_alg_method:
            self.tpmi_ecc_key_exchange = TpmAlg.tpm_alg_assymetric[tpmi_ecc_key_exchange]

        elif tpmi_ecc_key_exchang == 0x001B: #'TPM_ALG_SM2'
            self.tpmi_ecc_key_exchange = 'TPM_ALG_SM2'

        elif self.optional_value and tpmi_ecc_key_exchange == 0x0010: #'TPM_RH_NULL'
            self.tpmi_ecc_key_exchange = 'TPM_RH_NULL'

        else:  # just to be sure
            self.tpmi_ecc_key_exchange = hex(tpmi_ecc_key_exchange)

        return self.offset



class TpmsAlgorithmDetailEcc(TpmParser):
    """
    Page 127 Part 2 (TPMS_ALGORITHM_DETAIL_ECC) Structure <OUT> HERE
        -- curveID: TPM_ECC_CURVE: identifier for the curve
        -- keySize: UINT16: Size in bits of the key
        -- kdf: TPMT_KDF_SCHEME+: if not TPM_ALG_NULL, the required KDF and hash algorithm used in secret sharing operations
        -- sign: TPMT_ECC_SCHEME+: If not TPM_ALG_NULL, this is the mandatory signature scheme that is required to be used with this curve.
        -- p: TPM2B_ECC_PARAMETER: Fp (the modulus)
        -- a: TPM2B_ECC_PARAMETER: coefficient of the linear term in the curve equation
        -- b: TPM2B_ECC_PARAMETER: constant term for curve equation
        -- gx: TPM2B_ECC_PARAMETER: x coordinate of base point G
        -- gy: TPM2B_ECC_PARAMETER: y coordinate of base point G
        -- n: TPM2B_ECC_PARAMETER: order of G
        -- h: TPM2B_ECC_PARAMETER: cofactor (a size of zero indicates a cofactor of 1)
    """

    def __init__(self, tpm_command, offset, curve_id=None, key_size=0, kdf=None, sign=None, p=None, a=None, b=None, gx=None, gy=None, n=None, h=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.curve_id = curve_id
        self.key_size = key_size
        self.kdf = kdf
        self.sign = sign
        self.p = p
        self.a = a
        self.b = b
        self.gx = gx
        self.gy = gy
        self.n = n
        self.h = h 
        if (self.DEBUG):
            print(" [i] TPMS_ALGORITHM_DETAIL_ECC OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_ALGORITHM_DETAIL_ECC:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse curveID
        self.curve_id = TpmEccCurve(self.tpm_command, self.offset)
        self.offset = self.curve_id.parse()

        # Parse keySize
        self.key_size = self.parse_uint16()

        # Parse kdf
        self.kdf = TpmtKdfScheme(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.kdf.parse()

        # Parse sign
        self.sign = TpmtEccScheme(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.sign.parse()

        # Parse p
        self.p = Tpm2bEccParameter(self.tpm_command, self.offset)
        self.offset = self.p.parse()

        # Parse a
        self.a = Tpm2bEccParameter(self.tpm_command, self.offset)
        self.offset = self.a.parse()

        # Parse b
        self.b = Tpm2bEccParameter(self.tpm_command, self.offset)
        self.offset = self.b.parse()

        # Parse gx
        self.gx = Tpm2bEccParameter(self.tpm_command, self.offset)
        self.offset = self.gx.parse()

        # Parse gy
        self.gy = Tpm2bEccParameter(self.tpm_command, self.offset)
        self.offset = self.gy.parse()

        # Parse n
        self.n = Tpm2bEccParameter(self.tpm_command, self.offset)
        self.offset = self.n.parse()
        
        # Parse h
        self.h = Tpm2bEccParameter(self.tpm_command, self.offset)
        self.offset = self.h.parse()

        return self.offset



class TpmtTkVerified(TpmParser):
    """
    Page 96 Part 2 (TPMT_TK_VERIFIED) Structure
        -- tag {TPM_ST_VERIFIED}: TPM_ST: ticket structure tag
        -- hierarchy: TPMI_RH_HIERARCHY+: the hierarchy containing keyName
        -- digest: TPM2B_DIGEST: This shall be the HMAC produced using a proof value of hierarchy.
    """

    def __init__(self, tpm_command, offset, tag=None, hierarchy=None, digest=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.tag = tag
        self.hierarchy = hierarchy
        self.digest = digest
        if (self.DEBUG):
            print(" [i] TPMT_TK_VERIFIED OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_TK_VERIFIED:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse tag
        self.tag = TpmSt(self.tpm_command, self.offset)
        self.offset = self.tag.parse()

        # parse hierarchy
        self.hierarchy = TpmiRhHierarchy(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.hierarchy.parse()

        # parse digest
        self.digest = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.digest.parse()
        if self.digest.buf:
            self.digest.buf = "0x"+self.digest.buf.encode('hex')
        return self.offset



class Tpm2bAttest(TpmParser):
    """
    Page 111 Part 2 (TPM2B_ATTEST) Structure <OUT>
        -- size: UINT16: size of the attestationData structure
        -- attestationData[size]{::sizeof(TPMS_ATTEST)}: BYTE: the signed structure
    """

    def __init__(self, tpm_command, offset, size=0, attestation_data=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.size = size
        self.attestation_data = attestation_data
        if (self.DEBUG):
            print(" [i] TPM2B_ATTEST OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_ATTEST:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse size
        self.size = self.parse_uint16()

        # parse attestationData[[size]
        self.attestation_data = self.tpm_command[self.offset:self.offset+self.size]
        if self.attestation_data:
            self.attestation_data = "0x"+self.attestation_data.encode('hex')
        self.offset += self.size
        return self.offset



class TpmtTkAuth(TpmParser):
    """
    Page 97 Part 2 (TPMT_TK_AUTH) Structure
        -- tag {TPM_ST_AUTH_SIGNED, TPM_ST_AUTH_SECRET}: TPM_ST: ticket structure tag
        -- hierarchy: TPMI_RH_HIERARCHY+: the hierarchy of the object used to produce the ticket
        -- digest: TPM2B_DIGEST: This shall be the HMAC produced using a proof value of hierarchy.
    """

    def __init__(self, tpm_command, offset, tag=None, hierarchy=None, digest=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.tag = tag
        self.hierarchy = hierarchy
        self.digest = digest
        if (self.DEBUG):
            print(" [i] TPMT_TK_AUTH OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_TK_AUTH:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse tag
        self.tag = TpmSt(self.tpm_command, self.offset)
        self.offset = self.tag.parse()

        # parse hierarchy
        self.hierarchy = TpmiRhHierarchy(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.hierarchy.parse()

        # parse digest
        self.digest = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.digest.parse()
        if self.digest.buf:
            self.digest.buf = "0x"+self.digest.buf.encode('hex')
        return self.offset



class Tpm2bIdObject(TpmParser):
    """
    Page 139 Part 2 (TPM2B_ID_OBJECT) Structure
        -- size: UINT16: size of the credential structure
        -- credential[size]{::sizeof(TPMS_ID_OBJECT)}: BYTE: an encrypted credential area
    """

    def __init__(self, tpm_command, offset, size=0, credential=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.size = size
        self.credential = credential
        if (self.DEBUG):
            print(" [i] TPM2B_ID_OBJECT OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_ID_OBJECT:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse size
        self.size = self.parse_uint16()

        # parse credential[size]
        self.credential = self.tpm_command[self.offset:self.offset+self.size]
        if self.credential:
            self.credential = "0x"+self.credential.encode('hex')
        self.offset += self.size
        return self.offset



class TpmsSignatureEcc(TpmParser):
    """
    Page 128 Part 2 (TPMS_SIGNATURE_ECC) Structure
        -- hash: TPMI_ALG_HASH (TPM_ALG_!ALG.H): the hash algorithm used in the signature process. TPM_ALG_NULL is not allowed.
        -- signatureR: TPM2B_ECC_PARAMETER
        -- signatureS: TPM2B_ECC_PARAMETER
    """

    def __init__(self, tpm_command, offset, hash_value=None, signature_r=None, signature_s=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.hash_value = hash_value
        self.signature_r = signature_r
        self.signature_s = signature_s
        if (self.DEBUG):
            print(" [i] TPMS_SIGNATURE_ECC OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_SIGNATURE_ECC:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.hash = TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=False)
        self.offset = self.hash.parse()

        self.signature_r = Tpm2bEccParameter(self.tpm_command, self.offset)
        self.offset = self.signature_r.parse()

        self.signature_s = Tpm2bEccParameter(self.tpm_command, self.offset)
        self.offset = self.signature_s.parse()
        return self.offset



class TpmsSignatureRsa(TpmParser):
    """
    Page 127 Part 2 (TPMS_SIGNATURE_RSA) Structure
        -- hash: TPMI_ALG_HASH (TPM_ALG_!ALG.H): the hash algorithm used to digest the message. TPM_ALG_NULL is not allowed.
        -- sig: TPM2B_PUBLIC_KEY_RSA: The signature is the size of a public key.
    """

    def __init__(self, tpm_command, offset, hash_value=None, sig=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.hash_value = hash_value
        self.sig = sig
        if (self.DEBUG):
            print(" [i] TPMS_SIGNATURE_RSA OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_SIGNATURE_RSA:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.hash_value = TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=False)
        self.offset = self.hash_value.parse()

        self.sig = Tpm2bPublicKeyRsa(self.tpm_command, self.offset)
        self.offset = self.sig.parse()

        return self.offset



class TpmtSignature(TpmParser):
    """
    Page 128 Part 2 (TPMT_SIGNATURE) Structure
        -- sigAlg: +TPMI_ALG_SIG_SCHEME (TPM_ALG_!ALG.ax + TPM_ALG_HMAC + TPM_ALG_NULL): selector of the algorithm used to construct the signature
        -- [sigAlg]signature: TPMU_SIGNATURE: This shall be the actual signature information.
    """

    def __init__(self, tpm_command, offset, optional_value, sig_alg=None, sig_alg_signature=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.optional_value = optional_value
        self.sig_alg = sig_alg
        self.sig_alg_signature = sig_alg_signature
        if (self.DEBUG):
            print(" [i] TPMT_SIGNATURE OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_SIGNATURE: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.sig_alg = TpmAlg(self.tpm_command, self.offset, alg_types=['assymetric','signing'], optional_value=self.optional_value)
        #Note that TPM_ALG_HMAC is of type 'H X'. So we will catch this value for the current implementation
        self.offset = self.sig_alg.parse()

        self.sig_alg_signature = TpmuSignature(self.tpm_command, self.offset, self.sig_alg.tpm_alg)
        self.offset = self.sig_alg_signature.parse()
        return self.offset


class TpmuSignature(TpmParser):
    """
    Page 128 Part 2 (TPMU_SIGNATURE)
    Definition of TPMU_SIGNATURE Union
        'Parameter:Type:Selector'
        -- !ALG.ax:TPMS_SIGNATURE_!ALG.ax (TPMS_SIGNATURE_RSA for RSA and TPMS_SIGNATURE_ECC for ECC):TPM_ALG_!ALG.ax
        -- hmac: TPMT_HA: TPM_ALG_HMAC
        -- any:TPMS_SCHEME_HASH: 
        -- null: :TPM_ALG_NULL
    """    

    def __init__(self, tpm_command, offset, selector, enumerated_value=dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.selector = selector
        self.enumerated_value = enumerated_value
        if (self.DEBUG):
            print(" [i] TPMU_SIGNATURE OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMU_SIGNATURE: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # TODO: Not sure about this part
        if self.selector in TpmAlg.tpm_alg_assymetric.values() and self.selector in TpmAlg.tpm_alg_signing.values():
            if self.selector in TpmAlg.tpm_ecc_algs.values():
                self.enumerated_value = {'!ALG.ax':TpmsSignatureEcc(self.tpm_command, self.offset)}
                self.offset = self.enumerated_value['!ALG.ax'].parse()
            elif self.selector in TpmAlg.tpm_rsa_algs.values():
                self.enumerated_value = {'!ALG.ax':TpmsSignatureRsa(self.tpm_command, self.offset)}
                self.offset = self.enumerated_value['!ALG.ax'].parse()
        elif self.selector == "TPM_ALG_HMAC":
            self.enumerated_value = {'hmac':TpmtHa(self.tpm_command, self.offset, optional_value=False)}
            self.offset = self.enumerated_value['hmac'].parse()
        # elif:#TODO: Do not know what to do for TPMS_SCHEME_HASH
        elif self.selector == "TPM_ALG_NULL":
            self.enumerated_value = {'null':'NULL'}
        return self.offset



class TpmtSigScheme(TpmParser):
    """
    Page 120 Part 2 (TPMT_SIG_SCHEME) Structure
        -- scheme: +TPMI_ALG_SIG_SCHEME (TPM_ALG_!ALG.ax + TPM_ALG_HMAC + TPM_ALG_NULL): scheme selector
        -- [scheme]details: TPMU_SIG_SCHEME: scheme parameters
    """

    def __init__(self, tpm_command, offset, optional_value, scheme=None, scheme_details=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.optional_value = optional_value
        self.scheme = scheme
        self.scheme_details = scheme_details
        if (self.DEBUG):
            print(" [i] TPMT_SIG_SCHEME OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_SIG_SCHEME: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.scheme = TpmAlg(self.tpm_command, self.offset, alg_types=['assymetric','signing'], optional_value=self.optional_value)
        #Note that TPM_ALG_HMAC is of type 'H X'. So we will catch this value for the current implementation
        self.offset = self.scheme.parse()

        self.scheme_details = TpmuSigScheme(self.tpm_command, self.offset, self.scheme.tpm_alg)
        self.offset = self.scheme_details.parse()
        return self.offset



class TpmuSigScheme(TpmParser):
    """
    Page 120 Part 2 (TPMU_SIG_SCHEME)
    Definition of TPMU_SIG_SCHEME Union
        'Parameter:Type:Selector'
        -- !ALG.ax:TPMS_SIG_SCHEME_!ALG:TPM_ALG_!ALG: all signing schemes including anonymous schemes #TODO: not sure about this
        -- hmac: TPMS_SCHEME_HMAC (TPMS_SCHEME_HASH --> TPMI_ALG_HASH --> TPM_ALG_!ALG.H): TPM_ALG_HMAC
        -- any:TPMS_SCHEME_HASH: 
        -- null: :TPM_ALG_NULL
    """    

    def __init__(self, tpm_command, offset, selector, enumerated_value=dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.selector = selector
        self.enumerated_value = enumerated_value
        if (self.DEBUG):
            print(" [i] TPMU_SIG_SCHEME OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMU_SIG_SCHEME: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        #TODO: Maybe the ALG.xy is a specific set and not a subset?
        if self.selector in TpmAlg.tpm_alg_assymetric.values() and self.selector in TpmAlg.tpm_alg_signing.values():
            self.enumerated_value = {'!ALG.ax':TpmsSigScheme(self.tpm_command, self.offset, key_scheme_type=self.selector)}
            self.offset = self.enumerated_value['!ALG.ax'].parse() 
        elif self.selector == "TPM_ALG_HMAC":
            self.enumerated_value = {'hmac':TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=False)}
            self.offset = self.enumerated_value['hmac'].parse()
        # elif:#TODO: Do not know what to do for TPMS_SCHEME_HASH
        elif self.selector == "TPM_ALG_NULL": 
            self.enumerated_value = {'null':'NULL'}
        return self.offset



class Tpm2bEccPoint(TpmParser):
    """
    Page 125 Part 2 (TPM2B_ECC_POINT) Structure
        -- size=: UINT16: size of the remainder of this structure
        -- point: TPMS_ECC_POINT: coordinates
    """

    def __init__(self, tpm_command, offset, size_equals=0, point=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.size_equals = size_equals
        self.point = point
        if (self.DEBUG):
            print(" [i] TPM2B_ECC_POINT OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_ECC_POINT:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse size=
        self.size_equals = self.parse_uint16()

        # parse point
        self.point = TpmsEccPoint(self.tpm_command, self.offset)
        self.offset = self.point.parse()
        return self.offset



class TpmtTkHashcheck(TpmParser):
    """
    Page 98 Part 2 (TPMT_TK_HASHCHECK) Structure
        -- tag {TPM_ST_HASHCHECK} : TPM_ST: ticket structure tag
        -- hierarchy: TPMI_RH_HIERARCHY+: the hierarchy
        -- digest: TPM2B_DIGEST: This shall be the HMAC produced using a proof value of hierarchy.
    """

    def __init__(self, tpm_command, offset, tag=None, hierarchy=None, digest=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.tag = tag
        self.hierarchy = hierarchy
        self.digest = digest
        if (self.DEBUG):
            print(" [i] TPMT_TK_HASHCHECK OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_TK_HASHCHECK:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse tag
        self.tag = TpmSt(self.tpm_command, self.offset)
        self.offset = self.tag.parse()

        # parse hierarchy
        self.hierarchy = TpmiRhHierarchy(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.hierarchy.parse()

        # parse digest
        self.digest = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.digest.parse()
        if self.digest.buf:
            self.digest.buf = "0x"+self.digest.buf.encode('hex')
        return self.offset



class TpmlDigestValues(TpmParser):
    """
    Page 101 Part 2 (TPML_DIGEST_VALUES) Structure
        -- count : UINT32: number of digests in the list
        -- digests[count]{::HASH_COUNT}: TPMT_HA: a list of tagged digests
    """

    def __init__(self, tpm_command, offset, count=0, digests=list()):
        TpmParser.__init__(self, tpm_command, offset)
        self.count = count
        self.digests = list() #digests
        if (self.DEBUG):
            print(" [i] TPML_DIGEST_VALUES OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPML_DIGEST_VALUES:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse count
        self.count = self.parse_uint32()

        # parse digests[count]
        for i in range(self.count):
            digest = TpmtHa(self.tpm_command, self.offset, optional_value=False)
            self.offset = digest.parse()
            self.digests.append(digest)

        return self.offset



class TpmSe(TpmParser):
    """
    Page 45 Part 2 (UINT8) TPM_SE Constants <IN>
        -- TPM_SE_HMAC: 0x00
        -- TPM_SE_POLICY: 0x01
        -- TPM_SE_TRIAL: 0x03
    """

    TPM_SE = {0x00:'TPM_SE_HMAC', 0x01:'TPM_SE_POLICY', 0x03:'TPM_SE_TRIAL'}
    
    def __init__(self, tpm_command, offset, tpm_se=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.tpm_se = tpm_se
        if (self.DEBUG):
            print(" [i] TPM_SE OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM_SE:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        value = self.parse_uint8()
        if value in self.TPM_SE:
            self.tpm_se = self.TPM_SE[value]
        else:
            self.tpm_se = hex(value)
        return self.offset



class Tpm2bEncryptedSecret(TpmParser):
    """
    Page 129 Part 2 (TPM2B_ENCRYPTED_SECRET) Structure
        -- size: UINT16: size of the secret value
        -- secret[size] {::sizeof(TPMU_ENCRYPTED_SECRET)}: BYTE: secret
    """

    def __init__(self, tpm_command, offset, size=0, secret=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.size = size
        self.secret = secret
        if (self.DEBUG):
            print(" [i] TPM2B_ENCRYPTED_SECRET OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_ENCRYPTED_SECRET:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse size
        self.size = self.parse_uint16()

        # parse secret[size]
        self.secret = self.tpm_command[self.offset:self.offset+self.size]
        if self.secret:
            self.secret = "0x"+self.secret.encode('hex')
        self.offset += self.size
        return self.offset



class TpmiDhEntity(TpmParser):
    """
    Page 79 Part 2 (TPM_HANDLE) TPMI_DH_ENTITY Type <IN>
        -- TPM_RH_OWNER
        -- TPM_RH_PLATFORM
        -- TPM_RH_ENDORSEMENT
        -- TPM_RH_LOCKOUT
        -- {TRANSIENT_FIRST : TRANSIENT_LAST}: range of object handles
        -- {PERSISTENT_FIRST : PERSISTENT_LAST}
        -- {NV_INDEX_FIRST : NV_INDEX_LAST}
        -- {PCR_FIRST : PCR_LAST}
        -- {TPM_RH_AUTH_00 : TPM_RH_AUTH_FF}: range of vendor-specific authorization values
        -- +TPM_RH_NULL: conditional value
    """

    TPMI_DH_ENTITY={0x40000001:'TPM_RH_OWNER', 0x4000000C:'TPM_RH_PLATFORM', 0x4000000B:'TPM_RH_ENDORSEMENT', 0x4000000A:'TPM_RH_LOCKOUT'}
    
    def __init__(self, tpm_command, offset, optional_value, tpmi_dh_entity=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.tpmi_dh_entity = tpmi_dh_entity
        self.optional_value = optional_value
        if (self.DEBUG):
            print(" [i] TPMI_DH_ENTITY OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMI_DH_ENTITY:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.optional_value:
            self.TPMI_DH_ENTITY[0x40000007]='TPM_RH_NULL'
        dh_entity = self.parse_uint32()
        if dh_entity in self.TPMI_DH_ENTITY:
            self.tpmi_dh_entity = self.TPMI_DH_ENTITY[dh_entity]
        else:  # just to be sure
            self.tpmi_dh_entity = hex(dh_entity)
        return self.offset



class TpmlDigest(TpmParser):
    """
    Page 101 Part 2 (TPML_DIGEST) Structure
        -- count {2::}: UINT32: number of digests in the list, minimum is two for TPM2_PolicyOR().
        -- digests[count]{::8}: TPM2B_DIGEST: a list of digests...
    """

    def __init__(self, tpm_command, offset, count=0, digests=list()):
        TpmParser.__init__(self, tpm_command, offset)
        self.count = count
        self.digests = list() #digests
        if (self.DEBUG):
            print(" [i] TPML_DIGEST OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPML_DIGEST:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse count
        self.count = self.parse_uint32()

        # parse digests[count]
        for i in range(self.count):
            digest = Tpm2bDigest(self.tpm_command, self.offset)
            self.offset = digest.parse()
            if digest.buf:
                digest.buf = "0x"+digest.buf.encode('hex')
            self.digests.append(digest)

        return self.offset



class TpmCc(TpmParser):
    """
    Page 30 part 2 (UINT32) (TPM_CC) Constants
    """

    TPM_CC = { 0x0000011F:'TPM_CC_FIRST', 0x0000011F:'TPM_CC_NV_UndefineSpaceSpecial', 0x00000120:'TPM_CC_EvictControl', 0x00000121:'TPM_CC_HierarchyControl', 0x00000122:'TPM_CC_NV_UndefineSpace', 0x00000124:'TPM_CC_ChangeEPS', 0x00000125:'TPM_CC_ChangePPS', 0x00000126:'TPM_CC_Clear', 0x00000127:'TPM_CC_ClearControl', 0x00000128:'TPM_CC_ClockSet', 0x00000129:'TPM_CC_HierarchyChangeAuth', 0x0000012A:'TPM_CC_NV_DefineSpace', 0x0000012B:'TPM_CC_PCR_Allocate', 0x0000012C:'TPM_CC_PCR_SetAuthPolicy', 0x0000012D:'TPM_CC_PP_Commands', 0x0000012E:'TPM_CC_SetPrimaryPolicy', 0x0000012F:'TPM_CC_FieldUpgradeStart', 0x00000130:'TPM_CC_ClockRateAdjust', 0x00000131:'TPM_CC_CreatePrimary', 0x00000132:'TPM_CC_NV_GlobalWriteLock', 0x00000133:'TPM_CC_GetCommandAuditDigest', 0x00000134:'TPM_CC_NV_Increment', 0x00000135:'TPM_CC_NV_SetBits', 0x00000136:'TPM_CC_NV_Extend', 0x00000137:'TPM_CC_NV_Write', 0x00000138:'TPM_CC_NV_WriteLock', 0x00000139:'TPM_CC_DictionaryAttackLockReset', 0x0000013A:'TPM_CC_DictionaryAttackParameters', 0x0000013B:'TPM_CC_NV_ChangeAuth', 0x0000013C:'TPM_CC_PCR_Event', 0x0000013D:'TPM_CC_PCR_Reset', 0x0000013E:'TPM_CC_SequenceComplete', 0x0000013F:'TPM_CC_SetAlgorithmSet', 0x00000140:'TPM_CC_SetCommandCodeAuditStatus', 0x00000141:'TPM_CC_FieldUpgradeData', 0x00000142:'TPM_CC_IncrementalSelfTest', 0x00000143:'TPM_CC_SelfTest', 0x00000144:'TPM_CC_Startup', 0x00000145:'TPM_CC_Shutdown', 0x00000146:'TPM_CC_StirRandom', 0x00000147:'TPM_CC_ActivateCredential', 0x00000148:'TPM_CC_Certify', 0x00000149:'TPM_CC_PolicyNV', 0x0000014A:'TPM_CC_CertifyCreation', 0x0000014B:'TPM_CC_Duplicate', 0x0000014C:'TPM_CC_GetTime', 0x0000014D:'TPM_CC_GetSessionAuditDigest', 0x0000014E:'TPM_CC_NV_Read', 0x0000014F:'TPM_CC_NV_ReadLock', 0x00000150:'TPM_CC_ObjectChangeAuth', 0x00000151:'TPM_CC_PolicySecret', 0x00000152:'TPM_CC_Rewrap', 0x00000153:'TPM_CC_Create', 0x00000154:'TPM_CC_ECDH_ZGen', 0x00000155:'TPM_CC_HMAC', 0x00000156:'TPM_CC_Import', 0x00000157:'TPM_CC_Load', 0x00000158:'TPM_CC_Quote', 0x00000159:'TPM_CC_RSA_Decrypt', 0x0000015B:'TPM_CC_HMAC_Start', 0x0000015C:'TPM_CC_SequenceUpdate', 0x0000015D:'TPM_CC_Sign', 0x0000015E:'TPM_CC_Unseal', 0x00000160:'TPM_CC_PolicySigned', 0x00000161:'TPM_CC_ContextLoad', 0x00000162:'TPM_CC_ContextSave', 0x00000163:'TPM_CC_ECDH_KeyGen', 0x00000164:'TPM_CC_EncryptDecrypt', 0x00000165:'TPM_CC_FlushContext', 0x00000167:'TPM_CC_LoadExternal', 0x00000168:'TPM_CC_MakeCredential', 0x00000169:'TPM_CC_NV_ReadPublic', 0x0000016A:'TPM_CC_PolicyAuthorize', 0x0000016B:'TPM_CC_PolicyAuthValue', 0x0000016C:'TPM_CC_PolicyCommandCode', 0x0000016D:'TPM_CC_PolicyCounterTimer', 0x0000016E:'TPM_CC_PolicyCpHash', 0x0000016F:'TPM_CC_PolicyLocality', 0x00000170:'TPM_CC_PolicyNameHash', 0x00000171:'TPM_CC_PolicyOR', 0x00000172:'TPM_CC_PolicyTicket', 0x00000173:'TPM_CC_ReadPublic', 0x00000174:'TPM_CC_RSA_Encrypt', 0x00000176:'TPM_CC_StartAuthSession', 0x00000177:'TPM_CC_VerifySignature', 0x00000178:'TPM_CC_ECC_Parameters', 0x00000179:'TPM_CC_FirmwareRead', 0x0000017A:'TPM_CC_GetCapability', 0x0000017B:'TPM_CC_GetRandom', 0x0000017C:'TPM_CC_GetTestResult', 0x0000017D:'TPM_CC_Hash', 0x0000017E:'TPM_CC_PCR_Read', 0x0000017F:'TPM_CC_PolicyPCR', 0x00000180:'TPM_CC_PolicyRestart', 0x00000181:'TPM_CC_ReadClock', 0x00000182:'TPM_CC_PCR_Extend', 0x00000183:'TPM_CC_PCR_SetAuthValue', 0x00000184:'TPM_CC_NV_Certify', 0x00000185:'TPM_CC_EventSequenceComplete', 0x00000186:'TPM_CC_HashSequenceStart', 0x00000187:'TPM_CC_PolicyPhysicalPresence', 0x00000188:'TPM_CC_PolicyDuplicationSelect', 0x00000189:'TPM_CC_PolicyGetDigest', 0x0000018A:'TPM_CC_TestParms', 0x0000018B:'TPM_CC_Commit', 0x0000018C:'TPM_CC_PolicyPassword', 0x0000018D:'TPM_CC_ZGen_2Phase', 0x0000018E:'TPM_CC_EC_Ephemeral', 0x0000018F:'TPM_CC_PolicyNvWritten', 0x00000190:'TPM_CC_PolicyTemplate', 0x00000191:'TPM_CC_CreateLoaded', 0x00000192:'TPM_CC_PolicyAuthorizeNV', 0x00000193:'TPM_CC_EncryptDecrypt2'} #, 0x00000193:'TPM_CC_LAST'}

    def __init__(self, tpm_command, offset, tpm_cc=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.tpm_cc = tpm_cc
        if (self.DEBUG):
            print(" [i] TPM_CC OFFSET: {}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM_CC: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        value = self.parse_uint32()
        if value in self.TPM_CC:
            self.tpm_cc = self.TPM_CC[value]
        else:
            self.tpm_cc = hex(value)
        return self.offset



class TpmaAlgorithm(TpmParser):
    """
    Page 60 Part 2 (TPMA_ALGORITHM) (UINT32) Bits
        -- bit 0 asymmetric
        -- bit 1 symmetric
        -- bit 2 hash
        -- bit 3 object
        -- bit 4 Reserved
        -- bit 5 Reserved
        -- bit 6 Reserved
        -- bit 7 Reserved
        -- bit 8 signing
        -- bit 9 encrypting
        -- bit 10 method
        -- bit 11:31 reserved
    """
    tpma_algorithm_translation = {0:'asymmetric', 1:'symmetric', 2:'hash', 3:'object', 4:'Reserved', 5:'Reserved', 6:'Reserved', 7:'Reserved', 8:'signing', 9:'encrypting', 10:'method'} # > 10 reserved

    def __init__(self, tpm_command, offset, algorithm_attributes = dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.algorithm_attributes = algorithm_attributes
        if (self.DEBUG):
            print(" [i] TPMA_ALGORITHM OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMA_ALGORITHM:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        algorithm_attribute = self.parse_uint32()
        for bit in range(11):
            if( (algorithm_attribute >> bit & 1) == 1):
                self.algorithm_attributes[self.tpma_algorithm_translation[bit]] = 'SET'
            else:
                self.algorithm_attributes[self.tpma_algorithm_translation[bit]] = 'CLEAR'
        return self.offset



class TpmsAlgProperty(TpmParser):
    """
    Page 98 Part 2 (TPMS_ALG_PROPERTY) Structure <OUT>
        -- alg: TPM_ALG_ID: an algorithm identifier
        -- algProperties: TPMA_ALGORITHM: the attributes of the algorithm
    """

    def __init__(self, tpm_command, offset, alg=None, alg_properties=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.alg = alg
        self.alg_properties = alg_properties
        if (self.DEBUG):
            print(" [i] TPMS_ALG_PROPERTY OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_ALG_PROPERTY:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse alg
        self.alg = TpmAlg(self.tpm_command, self.offset, alg_types=['assymetric','symmetric','hash','signing','anonymous','encryption','method','object'], optional_value=True)
        self.offset = self.alg.parse()

        # parse algProperties
        self.alg_properties = TpmaAlgorithm(self.tpm_command, self.offset)
        self.offset = self.alg_properties.parse()
        return self.offset



class TpmlAlgProperty(TpmParser):
    """
    Page 102 Part 2 (TPML_ALG_PROPERTY) Structure <OUT>
        -- count: UINT32: number of algorithm properties structures. A value of zero is allowed.
        -- algProperties[count]{::MAX_CAP_ALGS}: TPMS_ALG_PROPERTY: list of properties
    """

    def __init__(self, tpm_command, offset, count=0, alg_properties=list()):
        TpmParser.__init__(self, tpm_command, offset)
        self.count = count
        self.alg_properties = list() #alg_properties
        if (self.DEBUG):
            print(" [i] TPML_ALG_PROPERTY OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPML_ALG_PROPERTY:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse count
        self.count = self.parse_uint32()

        # parse algProperties[count]
        for i in range(self.count):
            alg_property = TpmsAlgProperty(self.tpm_command, self.offset)
            self.offset = alg_property.parse()
            self.alg_properties.append(alg_property) 
        return self.offset



class TpmlHandle(TpmParser):
    """
    Page 100 Part 2 (TPML_HANDLE) Structure <OUT>
        -- count: UINT32: the number of handles in the list. may have a value of 0
        -- handle[count]{::MAX_CAP_HANDLES}: TPM_HANDLE: an array of handles
    """

    def __init__(self, tpm_command, offset, count=0, handle=list()):
        TpmParser.__init__(self, tpm_command, offset)
        self.count = count
        self.handle = list() #handle
        if (self.DEBUG):
            print(" [i] TPML_HANDLE OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPML_ALG_PROPERTY:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse count
        self.count = self.parse_uint32()

        # parse handle[count]
        for i in range(self.count):
            handle = hex(self.parse_uint32())
            self.handle.append(handle) 
        return self.offset



class TpmaCc(TpmParser):
    """
    Page 74 Part 2 (TPMA_CC) Bits <OUT> #TODO: Not sure if this is correct
        Bit: Name: Definition
        -- 15:0: commandIndex: indicates the command being selected
        -- 21:16: Reserved: shall be zero
        -- 22: nv: SET (1): indicates that the command may write to NV. CLEAR (0): indicates that the command does not write to NV
        -- 23: extensive: SET (1): This command could flush any number of loaded contexts. CLEAR (0): no additional changes other than indicated by the flushed attribute
        -- 24: flushed: SET (1): The context associated with any transient handle in the command will be flushed when this command completes. CLEAR (0): No context is flushed as a side effect of this command.
        -- 27:25: cHandles: indicates the number of the handles in the handle area for this command
        -- 28: rHandle: SET (1): indicates the presence of the handle area in the response
        -- 29: V: SET (1): indicates that the command is vendor-specific: CLEAR (0): indicates that the command is defined in a version of this specification
        -- 30-31: allocated for software; shall be zero
    """

    def __init__(self, tpm_command, offset, command_index=0, nv='', extensive='', flushed='', c_handles=0, r_handle='', v=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.command_index = command_index
        self.nv = nv
        self.extensive = extensive
        self.flushed = flushed
        self.c_handles = c_handles
        self.r_handle = r_handle
        self.v = v
        if (self.DEBUG):
            print(" [i] TPMA_CC OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMA_CC:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))

    def parse(self):
        tpma_cc = self.parse_uint32()
        # parse command_index
        self.command_index = tpma_cc & 0b1111111111111111

        # parse nv
        self.nv = tpma_cc >> 22 & 0b1
        if self.nv:
            self.nv = 'SET'
        else:
            self.nv = 'CLEAR'

        # parse extensive
        self.extensive = tpma_cc >> 23 & 0b1
        if self.extensive:
            self.extensive = 'SET'
        else:
            self.extensive = 'CLEAR'

        # parse flushed
        self.flushed = tpma_cc >> 24 & 0b1
        if self.flushed:
            self.flushed = 'SET'
        else:
            self.flushed = 'CLEAR'

        # parse cHandles
        self.c_handles = tpma_cc >> 25 & 0b111

        # parse rHandle
        self.r_handle = tpma_cc >> 28 & 0b1
        if self.r_handle:
            self.r_handle = 'SET'
        else:
            self.r_handle = 'CLEAR'

        # parse rHandle
        self.v = tpma_cc >> 29 & 0b1
        if self.v:
            self.v = 'SET'
        else:
            self.v = 'CLEAR'
        return self.offset



class TpmlCca(TpmParser):
    """
    Page 100 Part 2 (TPML_CCA) Structure <OUT>
        -- count: UINT32: number of values in the commandAttributes list. may be 0
        -- commandAttributes[count]{::MAX_CAP_CC}: TPMA_CC: a list of command codes attributes
    """

    def __init__(self, tpm_command, offset, count=0, command_attributes=list()):
        TpmParser.__init__(self, tpm_command, offset)
        self.count = count
        self.command_attributes = list() #command_attributes
        if (self.DEBUG):
            print(" [i] TPML_CCA OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPML_CCA:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))

    def parse(self):
        # parse count
        self.count = self.parse_uint32()

        # parse commandAttributes[count]
        for i in range(self.count):
            command_attr = TpmaCc(self.tpm_command, self.offset)
            self.offset = command_attr.parse()
            self.command_attributes.append(command_attr) 
        return self.offset



class TpmlCc(TpmParser):
    """
    Page 99 Part 2 (TPML_CC) Structure <OUT>
        -- count: UINT32: number of commands in the commandCode list;. may be 0
        -- commandCodes[count]{::MAX_CAP_CC}: TPM_CC: a list of command codes
    """

    def __init__(self, tpm_command, offset, count=0, command_codes=list()):
        TpmParser.__init__(self, tpm_command, offset)
        self.count = count
        self.command_codes = list() #command_codes
        if (self.DEBUG):
            print(" [i] TPML_CC OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPML_CC:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse count
        self.count = self.parse_uint32()

        # parse commandCodes[count]
        for i in range(self.count):
            command_code = self.TpmCc(self.tpm_command, self.offset)
            self.offset = command_code.parse()
            self.command_codes.append(command_code) 
        return self.offset



class TpmPt(TpmParser):
    """
    Page 47 part 2 (UINT32) (TPM_PT) (Property Tag)
    """

    PT_GROUP = 0x00000100
    PT_FIXED = PT_GROUP * 1
    PT_VAR = PT_GROUP * 2

    TPM_PT = {0x00000000 : 'TPM_PT_NONE', PT_FIXED + 0:'TPM_PT_FAMILY_INDICATOR', PT_FIXED + 1:'TPM_PT_LEVEL', PT_FIXED + 2:'TPM_PT_REVISION', PT_FIXED + 3:'TPM_PT_DAY_OF_YEAR', PT_FIXED + 4:'TPM_PT_YEAR', PT_FIXED + 5:'TPM_PT_MANUFACTURER', PT_FIXED + 6:'TPM_PT_VENDOR_STRING_1', PT_FIXED + 7:'TPM_PT_VENDOR_STRING_2', PT_FIXED + 8:'TPM_PT_VENDOR_STRING_3', PT_FIXED + 9:'TPM_PT_VENDOR_STRING_4', PT_FIXED + 10:'TPM_PT_VENDOR_TPM_TYPE', PT_FIXED + 11:'TPM_PT_FIRMWARE_VERSION_1', PT_FIXED + 12:'TPM_PT_FIRMWARE_VERSION_2', PT_FIXED + 13:'TPM_PT_INPUT_BUFFER', PT_FIXED + 14:'TPM_PT_HR_TRANSIENT_MIN', PT_FIXED + 15:'TPM_PT_HR_PERSISTENT_MIN', PT_FIXED + 16:'TPM_PT_HR_LOADED_MIN', PT_FIXED + 17:'TPM_PT_ACTIVE_SESSIONS_MAX', PT_FIXED + 18:'TPM_PT_PCR_COUNT ', PT_FIXED + 19:'TPM_PT_PCR_SELECT_MIN', PT_FIXED + 20:'TPM_PT_CONTEXT_GAP_MAX ', PT_FIXED + 22:'TPM_PT_NV_COUNTERS_MAX', PT_FIXED + 23:'TPM_PT_NV_INDEX_MAX', PT_FIXED + 24:'TPM_PT_MEMORY', PT_FIXED + 25:'TPM_PT_CLOCK_UPDATE', PT_FIXED + 26:'TPM_PT_CONTEXT_HASH', PT_FIXED + 27:'TPM_PT_CONTEXT_SYM', PT_FIXED + 28:'TPM_PT_CONTEXT_SYM_SIZE', PT_FIXED + 29:'TPM_PT_ORDERLY_COUNT', PT_FIXED + 30:'TPM_PT_MAX_COMMAND_SIZE', PT_FIXED + 31:'TPM_PT_MAX_RESPONSE_SIZE', PT_FIXED + 32:'TPM_PT_MAX_DIGEST', PT_FIXED + 33:'TPM_PT_MAX_OBJECT_CONTEXT', PT_FIXED + 34:'TPM_PT_MAX_SESSION_CONTEXT', PT_FIXED + 35:'TPM_PT_PS_FAMILY_INDICATOR', PT_FIXED + 36:'TPM_PT_PS_LEVEL', PT_FIXED + 37:'TPM_PT_PS_REVISION', PT_FIXED + 38:'TPM_PT_PS_DAY_OF_YEAR', PT_FIXED + 39:'TPM_PT_PS_YEAR', PT_FIXED + 40:'TPM_PT_SPLIT_MAX', PT_FIXED + 41:'TPM_PT_TOTAL_COMMANDS', PT_FIXED + 42:'TPM_PT_LIBRARY_COMMANDS', PT_FIXED + 43:'TPM_PT_VENDOR_COMMANDS', PT_FIXED + 44:'TPM_PT_NV_BUFFER_MAX', PT_FIXED + 45:'TPM_PT_MODES', PT_FIXED + 46:'TPM_PT_MAX_CAP_BUFFER', PT_VAR + 0:'TPM_PT_PERMANENT', PT_VAR + 1:'TPM_PT_STARTUP_CLEAR', PT_VAR + 2:'TPM_PT_HR_NV_INDEX', PT_VAR + 3:'TPM_PT_HR_LOADED', PT_VAR + 4:'TPM_PT_HR_LOADED_AVAIL', PT_VAR + 5:'TPM_PT_HR_ACTIVE', PT_VAR + 6:'TPM_PT_HR_ACTIVE_AVAIL', PT_VAR + 7:'TPM_PT_HR_TRANSIENT_AVAIL', PT_VAR + 8:'TPM_PT_HR_PERSISTENT', PT_VAR + 9:'TPM_PT_HR_PERSISTENT_AVAIL', PT_VAR + 10:'TPM_PT_NV_COUNTERS', PT_VAR + 11:'TPM_PT_NV_COUNTERS_AVAIL', PT_VAR + 12:'TPM_PT_ALGORITHM_SET', PT_VAR + 13:'TPM_PT_LOADED_CURVES', PT_VAR + 14:'TPM_PT_LOCKOUT_COUNTER', PT_VAR + 15:'TPM_PT_MAX_AUTH_FAIL', PT_VAR + 16:'TPM_PT_LOCKOUT_INTERVAL', PT_VAR + 17:'TPM_PT_LOCKOUT_RECOVERY', PT_VAR + 18:'TPM_PT_NV_WRITE_RECOVERY', PT_VAR + 19:'TPM_PT_AUDIT_COUNTER_0', PT_VAR + 20:'TPM_PT_AUDIT_COUNTER_1'}

    def __init__(self, tpm_command, offset, tpm_pt=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.tpm_pt = tpm_pt
        if (self.DEBUG):
            print(" [i] TPM_PT OFFSET: {}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM_PT: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))

    def parse(self):
        value = self.parse_uint32()
        if value in self.TPM_PT:
            self.tpm_pt = self.TPM_PT[value]
        else:
            self.tpm_pt = value
        return self.offset



class TpmsTaggedProperty(TpmParser):
    """
    Page 98 Part 2 (TPMS_TAGGED_PROPERTY) Structure <OUT>
        -- property: TPM_PT: a property identifier
        -- value: UINT32: the value of the property
    """

    def __init__(self, tpm_command, offset, tpms_tagged_property=None, value=0):
        TpmParser.__init__(self, tpm_command, offset)
        self.tpms_tagged_property = tpms_tagged_property
        self.value = value
        if (self.DEBUG):
            print(" [i] TPMS_TAGGED_PROPERTY OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_TAGGED_PROPERTY:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse property
        self.tpms_tagged_property = TpmPt(self.tpm_command, self.offset)
        self.offset = self.tpms_tagged_property.parse()

        # parse value
        self.value = self.parse_uint32()
        return self.offset



class TpmlTaggedTpmProperty(TpmParser):
    """
    Page 102 Part 2 (TPML_TAGGED_TPM_PROPERTY) Structure <OUT>
        -- count: UINT32: number of properties; A value of zero is allowed.
        -- tpmProperty[count]{::MAX_TPM_PROPERTIES}: TPMS_TAGGED_PROPERTY: an array of tagged properties
    """

    def __init__(self, tpm_command, offset, count=0, tpm_property=list()):
        TpmParser.__init__(self, tpm_command, offset)
        self.count = count
        self.tpm_property = list() #tpm_property
        if (self.DEBUG):
            print(" [i] TPML_TAGGED_TPM_PROPERTY OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPML_TAGGED_TPM_PROPERTY:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse count
        self.count = self.parse_uint32()

        # parse tpmProperty[count]
        for i in range(self.count):
            tpm_property = TpmsTaggedProperty(self.tpm_command, self.offset)
            self.offset = tpm_property.parse()
            self.tpm_property.append(tpm_property) 
        return self.offset



class TpmPtPcr(TpmParser):
    """
    Page 52 part 2 (UINT32) (TPM_PT_PCR) Constants <IN/OUT, S>
    """

    TPM_PT_PCR = {0x00000000:'TPM_PT_PCR_SAVE',0x00000001:'TPM_PT_PCR_EXTEND_L0',0x00000002:'TPM_PT_PCR_RESET_L0',0x00000003:'TPM_PT_PCR_EXTEND_L1',0x00000004:'TPM_PT_PCR_RESET_L1', 0x00000005:'TPM_PT_PCR_EXTEND_L2', 0x00000006:'TPM_PT_PCR_RESET_L2', 0x00000007:'TPM_PT_PCR_EXTEND_L3', 0x00000008:'TPM_PT_PCR_RESET_L3', 0x00000009:'TPM_PT_PCR_EXTEND_L4', 0x0000000A:'TPM_PT_PCR_RESET_L4', 0x00000011:'TPM_PT_PCR_NO_INCREMENT',0x00000012:'TPM_PT_PCR_DRTM_RESET', 0x00000013:'TPM_PT_PCR_POLICY', 0x00000014:'TPM_PT_PCR_AUTH'}

    def __init__(self, tpm_command, offset, tpm_pt_pcr=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.tpm_pt_pcr = tpm_pt_pcr
        if (self.DEBUG):
            print(" [i] TPM_PT_PCR OFFSET: {}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM_PT_PCR: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))

    def parse(self):
        value = self.parse_uint32()
        if value in self.TPM_PT_PCR:
            self.tpm_pt_pcr = self.TPM_PT_PCR[value]
        else:
            self.tpm_pt_pcr = hex(value)
        return self.offset



class TpmsTaggedPcrSelect(TpmParser):
    """
    Page 99 Part 2 (TPMS_TAGGED_PCR_SELECT) Structure <OUT>
        -- tag: TPM_PT_PCR: the property identifier
        -- sizeofSelect {PCR_SELECT_MIN::}: UINT8: the size in octets of the pcrSelect array
        -- pcrSelect[sizeofSelect] {::PCR_SELECT_MAX}: BYTE: the bit map of PCR with the identified property
    """

    def __init__(self, tpm_command, offset, tag=None, size_of_select=0, pcr_select=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.tag = tag
        self.size_of_select = size_of_select
        self.pcr_select = pcr_select
        if (self.DEBUG):
            print(" [i] TPMS_TAGGED_PCR_SELECT OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_TAGGED_PCR_SELECT:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse tag
        self.tag = TpmPtPcr(self.tpm_command, self.offset)
        self.offset = self.tag.parse()

        # parse size_of_select
        self.size_of_select = self.parse_uint8()

        # parse pcrSelect[sizeofSelect]
        self.pcr_select = self.tpm_command[self.offset:self.offset+self.size_of_select]
        if self.pcr_select:
            self.pcr_select = "0x"+self.pcr_select.encode('hex')
        self.offset += self.size_of_select
        return self.offset



class TpmlTaggedPcrProperty(TpmParser):
    """
    Page 103 Part 2 (TPML_TAGGED_PCR_PROPERTY) Structure <OUT>
        -- count: UINT32: number of properties; A value of zero is allowed.
        -- pcrProperty[count]{::MAX_PCR_PROPERTIES}: TPMS_TAGGED_PCR_SELECT: a tagged PCR selection
    """

    def __init__(self, tpm_command, offset, count=0, pcr_property=list()):
        TpmParser.__init__(self, tpm_command, offset)
        self.count = count
        self.pcr_property = list() #pcr_property
        if (self.DEBUG):
            print(" [i] TPML_TAGGED_PCR_PROPERTY OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPML_TAGGED_PCR_PROPERTY:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse count
        self.count = self.parse_uint32()

        # parse pcrProperty[count]
        for i in range(self.count):
            pcr_property = TpmsTaggedPcrSelect(self.tpm_command, self.offset)
            self.offset = pcr_property.parse()
            self.pcr_property.append(pcr_property) 
        return self.offset



class TpmEccCurve(TpmParser):
    """
    Page 28 part 2 (UINT16) (TPM_ECC_CURVE) Constants <IN/OUT, S>
    """

    TPM_ECC_CURVE = {0x0000:'TPM_ECC_NONE', 0x0001:'TPM_ECC_NIST_P192', 0x0002:'TPM_ECC_NIST_P224', 0x0003:'TPM_ECC_NIST_P256', 0x0004:'TPM_ECC_NIST_P384', 0x0005:'TPM_ECC_NIST_P521', 0x0010:'TPM_ECC_BN_P256', 0x0011:'TPM_ECC_BN_P638', 0x0020:'TPM_ECC_SM2_P256'}

    def __init__(self, tpm_command, offset, tpm_ecc_curve=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.tpm_ecc_curve = tpm_ecc_curve
        if (self.DEBUG):
            print(" [i] TPM_ECC_CURVE OFFSET: {}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM_ECC_CURVE: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))

    def parse(self):
        value = self.parse_uint16()
        if value in self.TPM_ECC_CURVE:
            self.tpm_ecc_curve = self.TPM_ECC_CURVE[value]
        else:
            self.tpm_ecc_curve = hex(value)
        return self.offset



class TpmlEccCurve(TpmParser):
    """
    Page 103 Part 2 (TPML_ECC_CURVE) Structure <OUT>
        -- count: UINT32: number of curves; A value of zero is allowed.
        -- eccCurves[count]{:MAX_ECC_CURVES}: TPM_ECC_CURVE: array of ECC curve identifiers
    """

    def __init__(self, tpm_command, offset, count=0, ecc_curves=list()):
        TpmParser.__init__(self, tpm_command, offset)
        self.count = count
        self.ecc_curves = list() #ecc_curves
        if (self.DEBUG):
            print(" [i] TPML_ECC_CURVE OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPML_ECC_CURVE:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse count
        self.count = self.parse_uint32()

        # parse eccCurves[count]
        for i in range(self.count):
            ecc_curve = TpmEccCurve(self.tpm_command, self.offset)
            self.offset = ecc_curve.parse()
            self.ecc_curves.append(ecc_curve) 
        return self.offset



class TpmuHa(TpmParser):
    """
    Definition of (TPMU_HA) Union <IN/OUT, S>
    Page 88 Part 2
           Parameter: Type: Selector
        -- !ALG.H [!ALG.H_DIGEST_SIZE]: BYTE: TPM_ALG_!ALG.H: all hashes
        -- null: : TPM_ALG_NULL
    """

    def __init__(self, tpm_command, offset, selector, enumerated_value=dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.selector = selector  # The selector used in order to properly match at the union
        self.enumerated_value = enumerated_value  # custom dict in order to catch all cases
        if (self.DEBUG):
            print(" [i] TPMU_HA OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMU_HA: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset','selector']))


    def parse(self):
        if self.selector == 'TPM_ALG_NULL':
            self.enumerated_value = {'Null':'null'}  # Not sure about this
        elif self.selector in TpmAlg.tpm_alg_hash.values():
            size = 0
            if self.selector == 'TPM_ALG_SHA' or self.selector == 'TPM_ALG_SHA1':
                size = 20
            elif self.selector == 'TPM_ALG_SHA256':
                size = 32
            elif self.selector == 'TPM_ALG_SHA384':
                size = 48
            elif self.selector == 'TPM_ALG_SHA512':
                size = 64
            hash_digest = self.tpm_command[self.offset:self.offset+size]
            if hash_digest:
                hash_digest = "0x"+hash_digest.encode('hex')
            self.enumerated_value = {'digest':hash_digest}
            self.offset += size
            #TODO: Probably add more values
        return self.offset



class TpmtHa(TpmParser):
    """
    Page 89 Part 2 (TPMT_HA) Structure <IN/OUT>
        -- hashAlg: +TPMI_ALG_HASH (TPM_ALG_!ALG.H , TPM_ALG_NULL): selector of the hash contained in the digest that implies the size of the digest
        -- [hashAlg] digest: TPMU_HA: the digest data
    """

    def __init__(self, tpm_command, offset, optional_value, hash_alg=None, digest=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.optional_value = optional_value
        self.hash_alg = hash_alg
        self.digest = digest
        if (self.DEBUG):
            print(" [i] TPMT_HA OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_HA: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse hash_alg
        self.hash_alg = TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=self.optional_value)
        self.offset = self.hash_alg.parse()
        
        # parse [hashAlg] digest
        self.digest = TpmuHa(self.tpm_command, self.offset, selector=self.hash_alg.tpm_alg)
        self.offset = self.digest.parse()
        
        return self.offset



class TpmsTaggedPolicy(TpmParser):
    """
    Page 99 Part 2 (TPMS_TAGGED_POLICY) Structure <OUT>
        -- handle: TPM_HANDLE: a permanent handle
        -- policyHash: TPMT_HA: the policy algorithm and hash
    """

    def __init__(self, tpm_command, offset, handle=0, policy_hash=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.handle = handle
        self.policy_hash = policy_hash
        if (self.DEBUG):
            print(" [i] TPMS_TAGGED_POLICY OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_TAGGED_POLICY:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse handle
        self.handle = hex(self.parse_uint32())

        # parse policy_hash
        self.policy_hash = TpmtHa(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.policy_hash.parse()
        return self.offset



class TpmlTaggedPolicy(TpmParser):
    """
    Page 103 Part 2 (TPML_TAGGED_POLICY) Structure <OUT>
        -- count: UINT32: number of tagged policies; A value of zero is allowed.
        -- policies[count]{:MAX_TAGGED_POLICIES}: TPMS_TAGGED_POLICY: array of tagged policies
    """

    def __init__(self, tpm_command, offset, count=0, policies=list()):
        TpmParser.__init__(self, tpm_command, offset)
        self.count = count
        self.policies = list() #policies
        if (self.DEBUG):
            print(" [i] TPML_TAGGED_POLICY OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPML_TAGGED_POLICY:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse count
        self.count = self.parse_uint32()

        # parse policies[count]
        for i in range(self.count):
            policy = TpmsTaggedPolicy(self.tpm_command, self.offset)
            self.offset = policy.parse()
            self.policies.append(policy) 
        return self.offset



class TpmUCapabilities(TpmParser):
    """
    Definition of (TPMU_CAPABILITIES) Union <OUT>
    Page 104 Part 2
           Parameter: Type: Selector
        -- algorithms: TPML_ALG_PROPERTY: TPM_CAP_ALGS
        -- handles: TPML_HANDLE: TPM_CAP_HANDLES
        -- command: TPML_CCA: TPM_CAP_COMMANDS
        -- ppCommands: : TPML_CC: TPM_CAP_PP_COMMANDS
        -- auditCommands: TPML_CC: TPM_CAP_AUDIT_COMMANDS
        -- assignedPCR: TPML_PCR_SELECTION: TPM_CAP_PCRS
        -- tpmProperties: TPML_TAGGED_TPM_PROPERTY: TPM_CAP_TPM_PROPERTIES
        -- pcrProperties: TPML_TAGGED_PCR_PROPERTY: TPM_CAP_PCR_PROPERTIES
        -- eccCurves: TPML_ECC_CURVE: TPM_CAP_ECC_CURVES: TPM_ALG_ECC
        -- authPolicies: TPML_TAGGED_POLICY: TPM_CAP_AUTH_POLICIES
    """

    def __init__(self, tpm_command, offset, selector, enumerated_value=dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.selector = selector  # The selector used in order to properly match at the union
        self.enumerated_value = enumerated_value  # custom dict in order to catch all cases
        if (self.DEBUG):
            print(" [i] TPMU_CAPABILITIES OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMU_CAPABILITIES: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset','selector']))


    def parse(self):
        if self.selector == 'TPM_CAP_ALGS': #TODO if the value is not found we should go to the closest
            self.enumerated_value = {'algorithms':TpmlAlgProperty(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['algorithms'].parse()
        elif self.selector == 'TPM_CAP_HANDLES':
            self.enumerated_value = {'handles':TpmlHandle(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['handles'].parse()
        elif self.selector == 'TPM_CAP_COMMANDS':
            self.enumerated_value = {'command':TpmlCca(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['command'].parse()
        elif self.selector == 'TPM_CAP_PP_COMMANDS':
            self.enumerated_value = {'ppCommands':TpmlCc(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['ppCommands'].parse()
        elif self.selector == 'TPM_CAP_AUDIT_COMMANDS':
            self.enumerated_value = {'auditCommands':TpmlCc(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['auditCommands'].parse()
        elif self.selector == 'TPM_CAP_PCRS':
            self.enumerated_value = {'assignedPCR':TpmlPcrSelection(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['assignedPCR'].parse()
        elif self.selector == 'TPM_CAP_TPM_PROPERTIES':
            self.enumerated_value = {'tpmProperties':TpmlTaggedTpmProperty(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['tpmProperties'].parse()
        elif self.selector == 'TPM_CAP_PCR_PROPERTIES':
            self.enumerated_value = {'pcrProperties':TpmlTaggedPcrProperty(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['pcrProperties'].parse()
        elif self.selector == 'TPM_CAP_ECC_CURVES':
            self.enumerated_value = {'eccCurves':TpmlEccCurve(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['eccCurves'].parse()
        elif self.selector == 'TPM_CAP_AUTH_POLICIES':
            self.enumerated_value = {'authPolicies':TpmlTaggedPolicy(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['authPolicies'].parse()
        return self.offset



class TpmsCapabilityData(TpmParser):
    """
    Page 104 Part 2 (TPMS_CAPABILITY_DATA) Structure <OUT>
        -- capability: TPM_CAP: the capability
        -- [capability]data: TPMU_CAPABILITIES: the capability data
    """

    def __init__(self, tpm_command, offset, capability=None, data=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.capability = capability
        self.data = data
        if (self.DEBUG):
            print(" [i] TPMS_CAPABILITY_DATA OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_CAPABILITY_DATA:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # parse capability
        self.capability = TpmCap(self.tpm_command, self.offset)
        self.offset = self.capability.parse()

        # parse [capability]data 
        self.data = TpmUCapabilities(self.tpm_command, self.offset, selector=self.capability.tpm_cap)
        self.offset = self.data.parse()
        return self.offset



class TpmCap(TpmParser):
    """
    Page 46 part 2 (UINT32) (TPM_CAP) Constants
    """

    TPM_CAP = {0x00000000:'TPM_CAP_FIRST',0x00000001:'TPM_CAP_HANDLES',0x00000002:'TPM_CAP_COMMANDS',0x00000003:'TPM_CAP_PP_COMMANDS',0x00000004:'TPM_CAP_AUDIT_COMMANDS',0x00000005:'TPM_CAP_PCRS',0x00000006:'TPM_CAP_TPM_PROPERTIES',0x00000007:'TPM_CAP_PCR_PROPERTIES',0x00000008:'TPM_CAP_ECC_CURVES',0x00000009:'TPM_CAP_AUTH_POLICIES',0x00000009:'TPM_CAP_LAST'}

    def __init__(self, tpm_command, offset, tpm_cap=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.tpm_cap = tpm_cap
        if (self.DEBUG):
            print(" [i] TPM_CAP OFFSET: {}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM_CAP: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))

    def parse(self):
        value = self.parse_uint32()
        if value in self.TPM_CAP:
            self.tpm_cap = self.TPM_CAP[value]
        else:
            self.tpm_cap = hex(value)
        return self.offset



class TpmtRsaDecrypt(TpmParser):
    """
    Page 123 Part 2 (TPMT_RSA_DECRYPT) Structure
        -- scheme: +TPMI_ALG_RSA_DECRYPT (TPM_ALG_!ALG.ae + TPM_ALG_NULL): scheme selector
        -- [scheme]details: TPMU_ASYM_SCHEME: scheme parameters
    """

    def __init__(self, tpm_command, offset, optional_value, scheme=None, scheme_details=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.optional_value = optional_value
        self.scheme = scheme
        self.scheme_details = scheme_details
        if (self.DEBUG):
            print(" [i] TPMT_RSA_DECRYPT OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_RSA_DECRYPT: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.scheme = TpmAlg(self.tpm_command, self.offset, alg_types=['assymetric','encryption'], optional_value=self.optional_value)
        self.offset = self.scheme.parse()

        self.scheme_details = TpmuAsymScheme(self.tpm_command, self.offset, self.scheme.tpm_alg)
        self.offset = self.scheme_details.parse()

        return self.offset



class Tpm2bContextData(TpmParser):
    """
    Page 146 Part 2 (TPM2B_CONTEXT_DATA) Structure <IN/OUT>
        -- size: UINT16
        -- buffer[size] {::sizeof(TPMS_CONTEXT_DATA)}: BYTE 
    """

    def __init__(self, tpm_command, offset, size=0, buf=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.size = size
        self.buf = buf
        if (self.DEBUG):
            print(" [i] TPM2B_CONTEXT_DATA OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_CONTEXT_DATA:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.size = self.parse_uint16()
        self.buf = self.tpm_command[self.offset:self.offset+self.size]
        if self.buf:
            self.buf = "0x"+self.buf.encode('hex')
        self.offset += self.size
        return self.offset



class TpmsContext(TpmParser):
    """
    Page 147 Part 2 (TPMS_CONTEXT) Structure
        -- sequence: UINT64: the sequence number of the context
        -- savedHandle: TPMI_DH_CONTEXT: a handle indicating if the context is a session, object, or sequence object 
            Possible Values Page 80  Part 2
            {HMAC_SESSION_FIRST : HMAC_SESSION_LAST}
            {POLICY_SESSION_FIRST:POLICY_SESSION_LAST}
            {TRANSIENT_FIRST:TRANSIENT_LAST}
            #TPM_RC_VALUE
        -- hierarchy: TPMI_RH_HIERARCHY+: the hierarchy of the context
        -- contextBlob: TPM2B_CONTEXT_DATA: the context data and integrity HMAC
    """

    def __init__(self, tpm_command, offset, sequence=0, saved_handle=0, hierarchy=None, context_blob=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.sequence = sequence
        self.saved_handle = saved_handle
        self.hierarchy = hierarchy
        self.context_blob = context_blob
        if (self.DEBUG):
            print(" [i] TPMS_CONTEXT OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_CONTEXT:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.sequence = self.parse_uint64()
        self.saved_handle = hex(self.parse_uint32())
        self.hierarchy =  TpmiRhHierarchy(self.tpm_command, self.offset, True)
        self.offset = self.hierarchy.parse()
        self.context_blob = Tpm2bContextData(self.tpm_command, self.offset)
        self.offset = self.context_blob.parse()
        return self.offset



class TpmSt(TpmParser):
    """
    Page 43 part 2 (UINT16) (TPM_ST) Constants
    """

    TPM_ST = {0x00C4:'TPM_ST_RSP_COMMAND', 0X8000:'TPM_ST_NULL', 0x8001:'TPM_ST_NO_SESSIONS', 0x8002:'TPM_ST_SESSIONS', 0x8014:'TPM_ST_ATTEST_NV', 0x8015:'TPM_ST_ATTEST_COMMAND_AUDIT', 0x8016:'TPM_ST_ATTEST_SESSION_AUDIT', 0x8017:'TPM_ST_ATTEST_CERTIFY', 0x8018:'TPM_ST_ATTEST_QUOTE', 0x8019:'TPM_ST_ATTEST_TIME', 0x801A:'TPM_ST_ATTEST_CREATION',0x8021:'TPM_ST_CREATION', 0x8022:'TPM_ST_VERIFIED', 0x8023:'TPM_ST_AUTH_SECRET', 0x8024:'TPM_ST_HASHCHECK',0x8025:'TPM_ST_AUTH_SIGNED',0x8029:'TPM_ST_FU_MANIFEST'}


    def __init__(self, tpm_command, offset, tpm_st=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.tpm_st = tpm_st
        if (self.DEBUG):
            print(" [i] TPM_ST OFFSET: {}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM_ST: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))

    def parse(self):
        value = self.parse_uint16()
        if value in self.TPM_ST:
            self.tpm_st = self.TPM_ST[value]
        else:
            self.tpm_st = hex(value)
        return self.offset



class TpmiRhHierarchy(TpmParser):
    """
    Page 81 Part 2 (TPMI_RH_HIERARCHY) Type
        -- TPM_RH_OWNER: Storage hierarchy
        -- TPM_RH_PLATFORM: Platform hierarchy
        -- TPM_RH_ENDORSEMENT: Endorsement hierarchy
        -- +TPM_RH_NULL: no hierarchy
    """

    TPMI_RH_HIERARCHY = {0x40000001:'TPM_RH_OWNER', 0x4000000C:'TPM_RH_PLATFORM', 0x4000000D:'TPM_RH_PLATFORM_NV', 0x4000000B:'TPM_RH_ENDORSEMENT'}
    
    def __init__(self, tpm_command, offset, optional_value, tpmi_rh_hierarchy=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.optional_value = optional_value
        self.tpmi_rh_hierarchy = tpmi_rh_hierarchy
        if (self.DEBUG):
            print(" [i] TPMI_RH_HIERARCHY OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMI_RH_HIERARCHY:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.optional_value:
            self.TPMI_RH_HIERARCHY[0x40000007]='TPM_RH_NULL'
        value = self.parse_uint32()
        if value in self.TPMI_RH_HIERARCHY:
            self.tpmi_rh_hierarchy = self.TPMI_RH_HIERARCHY[value]
        else:
            self.tpmi_rh_hierarchy = hex(value)
        return self.offset



class Tpm2bDigest(TpmParser):
    """
    Page 90 Part 2 (TPM2B_DIGEST) Structure
        -- size: UINT16: size in octets of the buffer field; may be 0
        -- buffer[size]{::sizeof(TPMU_HA)}: BYTE: the buffer area that can be no larger than a digest
    """

    def __init__(self, tpm_command, offset, size=0, buf=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.size = size
        self.buf = buf
        if (self.DEBUG):
            print(" [i] TPM2B_DIGEST OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2b DIGEST:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.size = self.parse_uint16()
        self.buf = self.tpm_command[self.offset:self.offset+self.size]
        self.offset += self.size
        return self.offset



class Tpm2bIv(TpmParser):
    """
    Page 92 Part 2 (TPM2B_IV) Structure
        -- size: UINT16: size of the IV value. This value is fixed for a TPM implementation.
        -- buffer [size] {::MAX_SYM_BLOCK_SIZE}: BYTE: the IV value
    """

    def __init__(self, tpm_command, offset, size=0, buf=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.size = size
        self.buf = buf
        if (self.DEBUG):
            print(" [i] TPM2B_IV OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_IV:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.size = self.parse_uint16()
        self.buf = self.tpm_command[self.offset:self.offset+self.size]
        if self.buf:
            self.buf = "0x"+self.buf.encode('hex')
        self.offset += self.size
        return self.offset



class Tpm2bMaxBuffer(TpmParser):
    """
    Page 91 Part 2 (TPM2B_MAX_BUFFER) Structure
        -- size: UINT16: size of the buffer
        -- buffer [size] {::MAX_DIGEST_BUFFER}: BYTE: the operand. Note: MAX_DIGEST_BUFFER is TPM-dependent but is required to be at least 1,024.
    """

    def __init__(self, tpm_command, offset, size=0, buf=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.size = size
        self.buf = buf
        if (self.DEBUG):
            print(" [i] TPM2B_MAX_BUFFER OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_MAX_BUFFER:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.size = self.parse_uint16()
        self.buf = self.tpm_command[self.offset:self.offset+self.size]
        self.offset += self.size
        return self.offset



class Tpm2bSensitiveData(TpmParser):
    """
    page 116 part 2 (TPM2B_SENSITIVE_DATA) Structure
        -- size=: UINT16
        -- buffer[size]{: sizeof(TPMU_SENSITIVE_CREATE)}: BYTE: symmetic data for a created object or the label and context for a derived object
    """

    def __init__(self, tpm_command, offset, size=0, buf=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.size = size
        self.buf = buf
        if (self.DEBUG):
            print(" [i] TPM2B_SENSITIVE_DATA OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_SENSITIVE_DATA: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.size = self.parse_uint16()
        self.buf = self.tpm_command[self.offset:self.offset+self.size]
        self.offset += self.size
        return self.offset



class TpmsSensitiveCreate(TpmParser):
    """
    Page 116 Part 2 (TPMS_SENSITIVE_CREATE) Structure <IN>
        -- userAuth: TPM2B_AUTH (TPM2B_DIGEST Page 90 Page 2): the USER auth secret value 
        -- data: TPM2B_SENSITIVE_DATA: data to be sealed, a key, or derivation values
    """

    def __init__(self, tpm_command, offset, userAuth=None, data=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.userAuth = userAuth
        self.data = data
        if (self.DEBUG):
            print(" [i] TPMS_SENSITIVE_CREATE OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_SENSITIVE_CREATE: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.userAuth = Tpm2bDigest(self.tpm_command, self.offset) 
        self.offset = self.userAuth.parse()

        self.data = Tpm2bSensitiveData(self.tpm_command, self.offset)
        self.offset = self.data.parse()
        return self.offset



class TpmaSession(TpmParser):
    """
    Page 68 Part 2 (TPMA_SESSION) Bits <IN/OUT>
    We have a UINT8
        -- bit 0 continueSession
        -- bit 1 auditExclusive
        -- bit 2 auditReset
        -- bit 4:3 Reserved
        -- bit 5 decrypt
        -- bit 6 encrypt
        -- bit 7 audit 
    """
    session_attributes_translation = {0:'continueSession',1:'auditExclusive',2:'auditReset',3:'Reserved',4:'Reserved',5:'decrypt',6:'encrypt',7:'audit'}

    def __init__(self, tpm_command, offset, session_attributes=dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.session_attributes = session_attributes
        if (self.DEBUG):
            print(" [i] TPMA_SESSION OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMA_SESSION:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        session_attribute_byte = self.parse_uint8()
        for bit in range(8):
            if( (session_attribute_byte >> bit & 1) == 1):
                self.session_attributes[self.session_attributes_translation[bit]] = 'SET'
            else:
                self.session_attributes[self.session_attributes_translation[bit]] = 'CLEAR'
        return self.offset


class AuthorizationAreaC(TpmParser):
    """
    Page 86,87 Part 1 'Authorization Area of Command'
        -- authorization_size: 4 octets: In a command, the authorizationSize indicates the number of octets in all of the authorization structures in the Authorization Area of the command. The driver and the TPM use the authorizationSize field to determine the number of authorizations. After authorizationSize bytes have been processed, there are no more authorizations.
        -- authorization_area: TPMS_AUTH_COMMAND structures of total size 'authorization_size'
    """

    def __init__(self, tpm_command, offset, authorization_size=0, authorization_structures=list()):
        TpmParser.__init__(self, tpm_command, offset)
        self.authorization_size = authorization_size
        self.authorization_structures = list() #authorization_structures
        if (self.DEBUG):
            print(" [i] Authorization Area OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] Authorization Area STRUCTURE: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse authorizationSize
        self.authorization_size = self.parse_uint32()

        # Parse TPMS_AUTH_COMMAND structures
        exit_offset = self.offset + self.authorization_size  # The offset where the authorization areas end
        while self.offset < exit_offset:
            authorization = TpmsAuthCommand(self.tpm_command, self.offset)
            self.offset = authorization.parse()
            self.authorization_structures.append(authorization)
        return self.offset



class TpmsAuthCommand(TpmParser):
    """
    Page 111 part 2 (TPMS_AUTH_COMMAND Structure <IN>),  
        -- sessionHandle: TPMI_SH_AUTH_SESSION+: handle: 4 octets
        -- nonce: TPM2B_NONCE (TPM2B_DIGEST): the session nonce, may have Empty Buffer
            -- size field: 2 octets, number of octets in nonce
            -- nonce: buffer[size]{:sizeof(TPMU_HA)}
        -- session attributes: TPMA_SESSION: octet that indicates session usage (Page 68 Part 2)
        -- hmac: TPM2B_AUTH (TPM2B_DIGEST)
            -- size field: 2 octets indicating the number of octets in authorization
            -- authorization: octet array containing HMAC or password
    """

    def __init__(self, tpm_command, offset, session_handle='', nonce=None, session_attributes=None, hmac=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.session_handle = session_handle
        self.nonce = nonce
        self.session_attributes = session_attributes
        self.hmac = hmac
        if (self.DEBUG):
            print(" [i] TPMS_AUTH_COMMAND OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_AUTH_COMMAND STRUCTURE: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        # parse sessionHandle
        session_handle = self.parse_uint32()  # TODO: TRANSLATE and add HMAC options!!! to TPM_RS_PW
        if (session_handle == 0x40000009):  # TODO: delete me and add more options
            self.session_handle = 'TPM_RS_PW'
        else:
            self.session_handle = hex(session_handle)

        self.nonce = Tpm2bDigest(self.tpm_command, self.offset) #TPM2B_AUTH
        self.offset = self.nonce.parse()
        if self.nonce.buf:
            self.nonce.buf = "0x"+self.nonce.buf.encode('hex')

        self.session_attributes = TpmaSession(self.tpm_command,self.offset)
        self.offset = self.session_attributes.parse()

        self.hmac = Tpm2bDigest(self.tpm_command, self.offset) #TPM2B_AUTH
        self.offset = self.hmac.parse()
        return self.offset



class AuthorizationAreaR(TpmParser):
    """
    Page 86,87 Part 1 'Authorization Area of Response'
        -- session_count: If the responseCode is TPM_RC_SUCCESS, the response has the same number of sessions in the same order as the request. Otherwise, no authorization or audit sessions are present there are no more authorizations.
        In a response, parameterSize indicates the number of octets in the parameter area of the response and does not include the four octets of the parameterSize value.
        -- authorization_area: TPMS_AUTH_RESPONSE structures

        # NOTE: It seems we have 2 ways of processing the Authorization Structures.
        #    1) Continue parsing structures till the end of the command
        #    2) Just count the same number of structures as the ones present in the command. This path is followed.
    """

    def __init__(self, tpm_command, offset, session_count, authorization_area=list()):
        TpmParser.__init__(self, tpm_command, offset)
        self.session_count = session_count
        self.authorization_area = list() # authorization_area
        if (self.DEBUG):
            print(" [i] Authorization Area OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] Authorization Area STRUCTURE: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))

    def parse(self):

        # Parse TPMS_AUTH_RESPONSE structures
        for i in range(self.session_count):
            authorization_area = TpmsAuthResponse(self.tpm_command, self.offset)
            self.offset = authorization_area.parse()
            self.authorization_area.append(authorization_area)
        return self.offset



class TpmsAuthResponse(TpmParser):
    """
    Page 111 Part 2 (TPMS_AUTH_RESPONSE Structure <OUT>)
        --nonce:
            -- size field: A two-octet value indicating the number of octets in nonce (will be zero for a password authorization)
            -- nonce: If present, an octet array that contains a number chosen by the TPM
        -- session attributes: A single octet with bit fields that indicate session usage
        --hmac:
            -- size field: A two-octet value indicating the number of octets in acknowledgment
            -- acknowledgment: If present, an octet array that contains an HMAC
    """

    def __init__(self, tpm_command, offset, nonce=None, session_attributes=None, hmac=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.nonce = nonce
        self.session_attributes = session_attributes
        self.hmac = hmac
        if (self.DEBUG):
            print(" [i] TPMS_AUTH_RESPONSE OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_AUTH_RESPONSE STRUCTURE: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.nonce = Tpm2bDigest(self.tpm_command, self.offset) #TPM2B_AUTH
        self.offset = self.nonce.parse()
        if self.nonce.buf:
            self.nonce.buf = "0x"+self.nonce.buf.encode('hex')

        self.session_attributes = TpmaSession(self.tpm_command,self.offset)
        self.offset = self.session_attributes.parse()

        self.hmac = Tpm2bDigest(self.tpm_command, self.offset) #TPM2B_AUTH
        self.offset = self.hmac.parse()
        return self.offset



class Tpm2bSensitiveCreate(TpmParser):
    """
    page 117 part 2 (TPM2B_SENSITIVE_CREATE) Structure <IN, S>
        -- size=: UINT16: size of sensitive in octets (may not be zero) NOTE The userAuth and data parameters in this buffer may both be zero length but the minimum size of this parameter will be the sum of the size fields of the two parameters of the TPMS_SENSITIVE_CREATE.
        -- sensitive: TPMS_SENSITIVE_CREATE: data to be sealed or a symmetric key value.
    """

    def __init__(self, tpm_command, offset, size_equals=0, tpms_sensitive_create=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.size_equals = size_equals
        self.tpms_sensitive_create = tpms_sensitive_create
        if (self.DEBUG):
            print(" [i] TPM2B_SENSITIVE_CREATE OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_SENSITIVE_CREATE: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.size_equals = self.parse_uint16()
        self.tpms_sensitive_create = TpmsSensitiveCreate(self.tpm_command,self.offset)
        self.offset = self.tpms_sensitive_create.parse()
        return self.offset



class TpmAlg(TpmParser):
    """
    NOTE: We chose to parse algorithms based on Type since it seemed that it was used for filtering 
    Page 25,26 Part 2 (TPM_ALG_ID) Constants <IN/OUT, S>
    Available Types:
        -- A: Asymmetric algorithm with a public and private key
        -- S: Symmetric algorithm with only a private key
        -- H: Hash algorithm that compresses input data to a digest value or indicates a method that uses a hash
        -- X: Signing algorithm
        -- N: An anonymous signing algorithm
        -- E: An encryption algorighm
        -- M: A method such as a mask generation function
        -- O: an object type
    Available classification:
        -- A: Assigned
        -- S: TCG Standard
        -- L: TCG Legacy
    """
    tpm_alg_error = {0x0000:'TPM_ALG_ERROR'} 
    tpm_alg_null = {0x0010 :'TPM_ALG_NULL'}
    tpm_alg_assymetric = {0x0001:'TPM_ALG_RSA', 0x0008:'TPM_ALG_KEYEDHASH', 0x0014:'TPM_ALG_RSASSA', 0x0015:'TPM_ALG_RSAES', 0x0016:'TPM_ALG_RSAPSS', 0x0017: 'TPM_ALG_OAEP', 0x0018:'TPM_ALG_ECDSA', 0x0019:'TPM_ALG_ECDH', 0x001A:'TPM_ALG_ECDAA', 0x001B:'TPM_ALG_SM2', 0x001C:'TPM_ALG_ECSCHNORR', 0x001D:'TPM_ALG_ECMQV', 0x0023:'TPM_ALG_ECC'}
    tpm_alg_symmetric = {0x0006:'TPM_ALG_AES', 0x0008:'TPM_ALG_KEYEDHASH', 0x000A:'TPM_ALG_XOR', 0x0013:'TPM_ALG_SM4', 0x0025:'TPM_ALG_SYMCIPHER', 0x0026:'TPM_ALG_CAMELLIA', 0x0040:'TPM_ALG_CTR', 0x0041:'TPM_ALG_OFB', 0x0042:'TPM_ALG_CBC', 0x0043:'TPM_ALG_CFB', 0x0044:'TPM_ALG_ECB'}
    tpm_alg_hash = {0x0004:'TPM_ALG_SHA', 0x0004:'TPM_ALG_SHA1', 0x0005:'TPM_ALG_HMAC', 0x0007:'TPM_ALG_MGF1', 0x0008:'TPM_ALG_KEYEDHASH', 0x000A:'TPM_ALG_XOR', 0x000B:'TPM_ALG_SHA256',0x000C:'TPM_ALG_SHA384', 0x000D:'TPM_ALG_SHA512', 0x0012:'TPM_ALG_SM3_256', 0x0017: 'TPM_ALG_OAEP', 0x0020:'TPM_ALG_KDF1_SP800_56A', 0x0021:'TPM_ALG_KDF2', 0x0022:'TPM_ALG_KDF1_SP800_108'}
    tpm_alg_signing = {0x0005:'TPM_ALG_HMAC', 0x0008:'TPM_ALG_KEYEDHASH', 0x0014:'TPM_ALG_RSASSA', 0x0016:'TPM_ALG_RSAPSS', 0x0018:'TPM_ALG_ECDSA',  0x001A:'TPM_ALG_ECDAA', 0x001B:'TPM_ALG_SM2', 0x001C:'TPM_ALG_ECSCHNORR'}
    tpm_alg_anonymous = {0x0008:'TPM_ALG_KEYEDHASH',  0x001A:'TPM_ALG_ECDAA'}
    tpm_alg_encryption = {0x0008:'TPM_ALG_KEYEDHASH', 0x0015:'TPM_ALG_RSAES', 0x0017: 'TPM_ALG_OAEP', 0x0040:'TPM_ALG_CTR', 0x0041:'TPM_ALG_OFB', 0x0042:'TPM_ALG_CBC', 0x0043:'TPM_ALG_CFB', 0x0044:'TPM_ALG_ECB'}
    tpm_alg_method = {0x0007:'TPM_ALG_MGF1', 0x0008:'TPM_ALG_KEYEDHASH', 0x0019:'TPM_ALG_ECDH', 0x001D:'TPM_ALG_ECMQV',0x0020:'TPM_ALG_KDF1_SP800_56A', 0x0021:'TPM_ALG_KDF2', 0x0022:'TPM_ALG_KDF1_SP800_108'}
    tpm_alg_object = {0x0001:'TPM_ALG_RSA', 0x0008:'TPM_ALG_KEYEDHASH', 0x0023:'TPM_ALG_ECC', 0x0025:'TPM_ALG_SYMCIPHER'}
    tpm_rsa_algs = {0x0001:'TPM_ALG_RSA',0x0014:'TPM_ALG_RSASSA', 0x0015:'TPM_ALG_RSAES', 0x0016:'TPM_ALG_RSAPSS', 0x0017: 'TPM_ALG_OAEP'}
    tpm_ecc_algs = {0x0018:'TPM_ALG_ECDSA', 0x0019:'TPM_ALG_ECDH',  0x001A:'TPM_ALG_ECDAA', 0x001B:'TPM_ALG_SM2', 0x001C:'TPM_ALG_ECSCHNORR', 0x001D:'TPM_ALG_ECMQV', 0x0020:'TPM_ALG_KDF1_SP800_56A'}


    def __init__(self, tpm_command, offset, alg_types, optional_value, tpm_alg=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.alg_types = alg_types  # Used during filtering
        self.optional_value = optional_value  # Used during filtering 
        self.tpm_alg = tpm_alg  # Actual value read
        if (self.DEBUG):
            print(" [i] TPM_ALG OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM_ALG: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command', 'offset', 'optional_value', 'alg_types']))


    def parse(self):
        self.tpm_alg = self.parse_uint16()
        if self.optional_value and self.tpm_alg in self.tpm_alg_null.keys():
            self.tpm_alg = self.tpm_alg_null[self.tpm_alg]
        elif 'assymetric' in self.alg_types and self.tpm_alg in self.tpm_alg_assymetric.keys():
          self.tpm_alg = self.tpm_alg_assymetric[self.tpm_alg]
        elif 'symmetric' in self.alg_types and self.tpm_alg in self.tpm_alg_symmetric.keys():
          self.tpm_alg = self.tpm_alg_symmetric[self.tpm_alg]
        elif 'hash' in self.alg_types and self.tpm_alg in self.tpm_alg_hash.keys():
          self.tpm_alg = self.tpm_alg_hash[self.tpm_alg]
        elif 'signing' in self.alg_types and self.tpm_alg in self.tpm_alg_signing.keys():
          self.tpm_alg = self.tpm_alg_signing[self.tpm_alg]
        elif 'anonymous' in self.alg_types and self.tpm_alg in self.tpm_alg_anonymous.keys():
          self.tpm_alg = self.tpm_alg_anonymous[self.tpm_alg]
        elif 'encryption' in self.alg_types and self.tpm_alg in self.tpm_alg_encryption.keys():
          self.tpm_alg = self.tpm_alg_encryption[self.tpm_alg]
        elif 'method' in self.alg_types and self.tpm_alg in self.tpm_alg_method.keys():
          self.tpm_alg = tpm_alg_method[self.tpm_alg]
        elif 'object' in self.alg_types and self.tpm_alg in self.tpm_alg_object.keys():
            self.tpm_alg = self.tpm_alg_object[self.tpm_alg]
        return self.offset



class TpmaObject(TpmParser):
    """
    Page 61 Part 2 (TPMA_OBJECT) (UINT32) Bits
    We have a (UINT32)
        -- bit 0 Reserved
        -- bit 1 fixedTPM
        -- bit 2 stClear
        -- bit 3 Reserved
        -- bit 4 fixedParent
        -- bit 5 sensitiveDataOrigin
        -- bit 6 userWithAuth
        -- bit 7 adminWithPolicy
        -- bit 8:9 Reserved
        -- bit 10 noDA
        -- bit 11 encryptedDuplication
        -- bit 12:15 Reserved
        -- bit 16 restricted
        -- bit 17 decrypt
        -- bit 18 sign/encrypt
        -- bit 19:31 reserved
    """
    tpma_object_translation = {0:'Reserved', 1:'fixedTPM', 2:'stClear', 3:'Reserved', 4:'fixedParent', 5:'sensitiveDataOrigin', 6:'userWithAuth', 7:'adminWithPolicy', 8:'Reserved', 9:'Reserved', 10:'noDA', 11:'encryptedDuplication', 12:'Reserved', 13:'Reserved', 14:'Reserved', 15:'Reserved', 16:'restricted', 17:'decrypt', 18:'sign/encrypt'} # >18 Reserved

    def __init__(self, tpm_command, offset, object_attributes = dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.object_attributes = object_attributes
        if (self.DEBUG):
            print(" [i] TPMA_OBJECT OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMA_OBJECT\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        object_attribute = self.parse_uint32()
        for bit in range(19):
            if( (object_attribute >> bit & 1) == 1):
                self.object_attributes[self.tpma_object_translation[bit]] = 'SET'
            else:
                self.object_attributes[self.tpma_object_translation[bit]] = 'CLEAR'
        return self.offset



class TpmuSymKeyBits(TpmParser):
    """
    Definition of (TPMU_SYM_KEY_BITS) Union
    Page 112 Part 2
    Parameter: Type: Selector
        -- !ALG.S: TPMI_!ALG.S_KEY_BITS: TPM_ALG_!ALG.S
        -- sym: TPM_KEY_BITS
        -- xor: TPMI_ALG_HASH (TPM_ALG_!ALG.H): TPM_ALG_XOR
        -- null: : TPM_ALG_NULL
    """

    def __init__(self, tpm_command, offset, selector, enumerated_value=dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.selector = selector  # The selector used in order to properly match at the union
        self.enumerated_value = enumerated_value  # custom dict in order to catch all cases
        if (self.DEBUG):
            print(" [i] TPMU_SYM_KEY_BITS OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMU_SYM_KEY_BITS: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset','selector']))


    def parse(self):
        if self.selector in TpmAlg.tpm_alg_symmetric.values():
            self.enumerated_value = {'key_size':self.parse_uint16()}  # just a guess (regarding the size, but seems correct)
        # elif TPM_KEY_BITS # TODO: dont know how to handle this
        elif self.selector == 'TPM_ALG_XOR':
            self.enumerated_value = {'xor':TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=False)}
            self.offset = self.enumerated_value['xor'].parse()
        elif self.selector == 'TPM_ALG_NULL':
            self.enumerated_value = {'null':''}
        return self.offset



class TpmuSymMode(TpmParser):
    """
    Definition of (TPMU_SYM_MODE) Union
    Page 113 Part 2
    Parameter: Type: Selector
        -- !ALG.S: TPMI_ALG_SYM_MODE+ (TPM_ALG_!ALG.SE + NULL): TPM_ALG_!ALG.S
        -- sym: TPMI_ALG_SYM_MODE+:
        -- xor: : TPM_ALG_XOR
        -- null: : TPM_ALG_NULL
    """

    def __init__(self, tpm_command, offset, selector, enumerated_value=dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.selector = selector  # The selector used in order to properly match at the union
        self.enumerated_value = enumerated_value  # custom dict in order to catch all cases 
        if (self.DEBUG):
            print(" [i] TPMU_SYM_MODE OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMU_SYM_MODE: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset','selector']))


    def parse(self):
        if self.selector in TpmAlg.tpm_alg_symmetric.values():
            self.enumerated_value = {'sym_mode':TpmAlg(self.tpm_command, self.offset, alg_types=['symmetric','encryption'], optional_value=True)}
            self.offset = self.enumerated_value['sym_mode'].parse()
        # elif sym # TODO: dont know how to handle this
        elif self.selector == 'TPM_ALG_XOR':
            self.enumerated_value = {'xor':''}  #TODO: Is this correct?
        elif self.selector == 'TPM_ALG_NULL':
            self.enumerated_value = {'null':''}
        return self.offset



class TpmsKeyScheme(TpmParser):
    """
    Page 121 Part 2
    TPMS_KEY_SCHEME_!ALG.
    #IF TYPE IS ECC
    Definition of Types {ECC} ECC Key Exchange
    Type: Name: Description
        -- TPMS_SCHEME_HASH (TPMI_ALG_HASH --> TPM_ALG_!ALG.H): TPMS_KEY_SCHEME_!ALG.AM: schemes that need a hash
    """

    def __init__(self, tpm_command, offset, key_scheme_type, value=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.key_scheme_type = key_scheme_type
        self.value = value
        if (self.DEBUG):
            print(" [i] TPMS_KEY_SCHEME OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_KEY_SCHEME: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))

    def parse(self):
        # CASE OF ECC
        if self.key_scheme_type in TpmAlg.tpm_ecc_algs.values():
            if self.key_scheme_type in TpmAlg.tpm_alg_assymetric.values() and self.key_scheme_type in TpmAlg.tpm_alg_method.values():
                self.value = TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=False)
                self.offset = self.value.parse() 
        return self.offset



class TpmsSchemeEcdaa(TpmParser):
    """
    Page 117 Part 2 (TPMS_SCHEME_ECDAA) Structure
        -- hashAlg: TPMI_ALG_HASH (TPM_ALG_!ALG.H): the hash algorithm used to digest the message
        -- count: UINT16: the counter value that is used between TPM2_Commit() and the sign operation 

    """

    def __init__(self, tpm_command, offset, hash_alg=None, count=0):
        TpmParser.__init__(self, tpm_command, offset)
        self.hash_alg = hash_alg
        self.count = count
        if (self.DEBUG):
            print(" [i] TPMS_SCHEME_ECDAA OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_SCHEME_ECDAA:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Parse hashAlg
        self.hash_alg = TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=False)
        self.offset = self.hash_alg.parse()

        # Parse count
        self.count = self.parse_uint16()
        return self.offset



class TpmsSigScheme(TpmParser):
    """
    Page 119 Part 2
    TPMS_SIG_SCHEME_!ALG._
    
    #IF TYPE IS RSA
    Definition of {RSA} Types for RSA Signature Schemes
    Type: Name: Description
        -- TPMS_SCHEME_HASH (TPMI_ALG_HASH --> TPM_ALG_!ALG.H): TPMS_SIG_SCHEME_!ALG.AX
    
    #IF SIG_SCHEME ECC
    Definition of {ECC} Types for ECC Signature Schemes
    Type: Name: Description
        -- TPMS_SCHEME_HASH TPMI_ALG_HASH --> TPM_ALG_!ALG.H): TPMS_SIG_SCHEME_!ALG.AX: all asymmetric signing schemes
        -- TPMS_SCHEME_ECDAA: TPMS_SIG_SCHEME_!ALG.AXN: schemes that need a hash and a count

    """

    def __init__(self, tpm_command, offset, key_scheme_type, value=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.key_scheme_type = key_scheme_type
        self.value = value
        if (self.DEBUG):
            print(" [i] TPMS_SIG_SCHEME OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_SIG_SCHEME: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))

    def parse(self):
        #CASE OF RSA
        if self.key_scheme_type in TpmAlg.tpm_rsa_algs.values():
            self.value = TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=False)
            self.offset = self.value.parse()

        # CASE OF ECC
        elif self.key_scheme_type in TpmAlg.tpm_ecc_algs.values(): 
            if self.key_scheme_type in TpmAlg.tpm_alg_assymetric.values() and self.key_scheme_type in TpmAlg.tpm_alg_signing.values():  # ALG.AX
                if self.key_scheme_type in TpmAlg.tpm_alg_anonymous:  # ALG.AXN
                    self.value = TpmsSchemeEcdaa(self.tpm_command, self.offset)
                    self.offset = self.value.parse()        
                else:  # ALG.AX
                    self.value = TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=False)
                    self.offset = self.value.parse()  

        return self.offset



class TpmsEncScheme(TpmParser):
    """
    Page 120 Part 2
    TPMS_ENC_SCHEME_!ALG.
    
    #IF TYPE IS RSA
    Definition of Types for {RSA} Encryption Schemes
    Type: Name: Description
        -- TPMS_SCHEME_HASH (TPMI_ALG_HASH --> TPM_ALG_!ALG.H): TPMS_SIG_SCHEME_!ALG.AEH : schemes that only need a hash
        -- TPMS_EMPTY (a structure with no member): TPMS_ENC_SCHEME_!ALG.AE: schemes that need nothing
    """

    def __init__(self, tpm_command, offset, key_scheme_type, value=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.key_scheme_type = key_scheme_type
        self.value = value
        if (self.DEBUG):
            print(" [i] TPMS_ENC_SCHEME OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_ENC_SCHEME: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))

    def parse(self):
        # CASE OF RSA
        if self.key_scheme_type in TpmAlg.tpm_rsa_algs.values(): 
            if self.key_scheme_type in TpmAlg.tpm_alg_assymetric.values() and self.key_scheme_type in TpmAlg.tpm_alg_encryption.values():  # ALG.AE
                if self.key_scheme_type in TpmAlg.tpm_alg_hash:  # ALG.AEH
                    self.value = TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=False)
                    self.offset = self.value.parse()         
                # else:  # ALG.AE
                # no member so do nothing
        return self.offset



class TpmuAsymScheme(TpmParser):
    """
    Page 122 Part 2 (TPMU_ASYM_SCHEME)
    Definition of TPMU_ASYM_SCHEME Union
        'Parameter:Type:Selector' #TODO: not sure about this
        -- !ALG.am:TPMS_KEY_SCHEME_!ALG:TPM_ALG_!ALG
        -- !ALG.ax:TPMS_SIG_SCHEME_!ALG:TPM_ALG_!ALG 
        -- !ALG.ae:TPMS_ENC_SCHEME_!ALG:TPM_ALG_!ALG
        -- anySig:TPMS_SCHEME_HASH: 
        -- null: :TPM_ALG_NULL
    """    

    def __init__(self, tpm_command, offset, selector, enumerated_value=dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.selector = selector
        self.enumerated_value = enumerated_value
        if (self.DEBUG):
            print(" [i] TPMU_ASYM_SCHEME OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMU_ASYM_SCHEME: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        #TODO: Maybe the ALG.xy is a specific set and not a subset?
        if self.selector in TpmAlg.tpm_alg_assymetric.values() and self.selector in TpmAlg.tpm_alg_method.values():
            self.enumerated_value = {'!ALG.am':TpmsKeyScheme(self.tpm_command, self.offset, key_scheme_type=self.selector)}
            self.offset = self.enumerated_value['!ALG.am'].parse() 
        elif self.selector in TpmAlg.tpm_alg_assymetric.values() and self.selector in TpmAlg.tpm_alg_signing.values():
            self.enumerated_value = {'!ALG.ax':TpmsSigScheme(self.tpm_command, self.offset, key_scheme_type=self.selector)}
            self.offset = self.enumerated_value['!ALG.ax'].parse() 
        elif self.selector in TpmAlg.tpm_alg_assymetric.values() and self.selector in TpmAlg.tpm_alg_encryption.values():
            self.enumerated_value = {'!ALG.ae':TpmsEncScheme(self.tpm_command, self.offset, key_scheme_type=self.selector)}
            self.offset = self.enumerated_value['!ALG.ae'].parse() 
        # elif:#TODO: Do not know what to do for TPMS_SCHEME_HASH
        elif self.selector == "TPM_ALG_NULL":
            self.enumerated_value = {'null':'NULL'}
        return self.offset



class TpmtRsaScheme(TpmParser):
    """
    Page 123 Part 2 (TPMT_RSA_SCHEME) Structure
        -- scheme: +TPMI_ALG_RSA_SCHEME (TPM_ALG_!ALG.ae.ax + NULL): scheme selector
        -- [scheme]details: TPMU_ASYM_SCHEME: scheme parameters
    """

    def __init__(self, tpm_command, offset, optional_value, scheme=None, scheme_details=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.optional_value = optional_value
        self.scheme = scheme
        self.scheme_details = scheme_details
        if (self.DEBUG):
            print(" [i] TPMT_RSA_SCHEME OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_RSA_SCHEME: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.scheme = TpmAlg(self.tpm_command, self.offset, alg_types=['encryption','signing'], optional_value=self.optional_value)
        self.offset = self.scheme.parse()

        self.scheme_details = TpmuAsymScheme(self.tpm_command, self.offset, self.scheme.tpm_alg)
        self.offset = self.scheme_details.parse()

        return self.offset



class TpmtSymDefObject(TpmParser):
    """
    Page 114 Part 2 (TPMT_SYM_DEF_OBJECT) Structure
        -- algorithm: +TPMI_ALG_SYM_OBJECT (TPM_ALG_!ALG.S +NULL): selects a symmetric block cipher
        -- [algorithm]keyBits: TPMU_SYM_KEY_BITS: the key size
        -- [algorithm]mode: TPMU_SYM_MODE: default mode
        -- //[algorithm]details: TPMU_SYM_DETAILS: contains the additional algorithm details, if any
    """

    def __init__(self, tpm_command, offset, optional_value, algorithm=None, key_bits=None, mode=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.optional_value = optional_value
        self.algorithm = algorithm
        self.key_bits = key_bits
        self.mode = mode
        if (self.DEBUG):
            print(" [i] TPMT_SYM_DEF_OBJECT OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_SYM_DEF_OBJECT: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        self.algorithm = TpmAlg(self.tpm_command, self.offset, alg_types=['symmetric'], optional_value=self.optional_value)
        self.offset = self.algorithm.parse()

        self.key_bits = TpmuSymKeyBits(self.tpm_command, self.offset, self.algorithm.tpm_alg)
        self.offset = self.key_bits.parse()

        self.mode = TpmuSymMode(self.tpm_command, self.offset,self.algorithm.tpm_alg)
        self.offset = self.mode.parse()

        return self.offset



class TpmsSchemeXor(TpmParser):
    """
    Page 118 Part 2 (TPMS_SCHEME_XOR) Structure
        -- hashAlg: TPMI_ALG_HASH+ (TPM_ALG_!ALG.H + NULL): the hash algorithm used to digest the message
        -- kdf: TPMI_ALG_KDF+ (TPM_ALG_!ALG.HM + NULL): the key derivation function
    """
    
    def __init__(self, tpm_command, offset, hashAlg=None, kdf=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.hashAlg = hashAlg
        self.kdf = kdf
        if (self.DEBUG):
            print(" [i] TPMS_SCHEME_XOR OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_SCHEME_XOR: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.hashAlg = TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=True)
        self.offset = self.hashAlg.parse()

        self.kdf = TpmAlg(self.tpm_command, self.offset, alg_types=['hash','method'], optional_value=True)
        self.offset = self.kdf.parse()
        return self.offset



class TpmuSchemeKeyedhash(TpmParser):
    """
    Page 118 Part 2
    Definition of (TPMU_SCHEME_KEYEDHASH) Union <IN/OUT,S>
        Parameter: Type: Selector:
        -- hmac: TPMS_SCHEME_HMAC (TPMS_SCHEME_HASH --> TPMI_ALG_HASH --> TPM_ALG_!ALG.H): TPM_ALG_HMAC
        -- xor: TPMS_SCHEME_XOR: TPM_ALG_XOR
        -- null: : TPM_ALG_NULL
    """
    
    def __init__(self, tpm_command, offset, selector, enumerated_value=dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.selector = selector
        self.enumerated_value = enumerated_value
        if (self.DEBUG):
            print(" [i] TPMU_SCHEME_KEYEDHASH OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMU_SCHEME_KEYEDHASH: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.selector == "TPM_ALG_HMAC":
            self.enumerated_value = {'hmac':TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=False)}
            self.offset = self.enumerated_value['hmac'].parse()
        elif self.selector == "TPM_ALG_XOR":
            self.enumerated_value = {'xor':TpmsSchemeXor(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['xor'].parse()
        elif self.selector == "TPM_ALG_NULL":
            self.enumerated_value = {'null':'null'}
        return self.offset



class TpmtKeyedhashScheme(TpmParser):
    """
    Page 118 Part 2 (TPMT_KEYEDHASH_SCHEME) Structure
        -- scheme: +TPMI_ALG_KEYEDHASH_SCHEME: selects the scheme 
        -- [scheme]details: TPMU_SCHEME_KEYEDHASH: the scheme parameters
    """
    TPMI_ALG_KEYEDHASH_SCHEME = {0x0005:'TPM_ALG_HMAC',0x000A:"TPM_ALG_XOR"}

    def __init__(self, tpm_command, offset, optional_value, scheme='', scheme_details=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.optional_value = optional_value
        self.scheme = scheme
        self.scheme_details = scheme_details
        if (self.DEBUG):
            print(" [i] TPMT_KEYEDHASH_SCHEME OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_KEYEDHASH_SCHEME: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if(self.optional_value):
            self.TPMI_ALG_KEYEDHASH_SCHEME[0x0010] = "TPM_ALG_NULL"
        value = self.parse_uint16()
        if value in self.TPMI_ALG_KEYEDHASH_SCHEME:
            self.scheme = self.TPMI_ALG_KEYEDHASH_SCHEME[value]
        else:
            self.scheme = hex(value)
        
        self.scheme_details = TpmuSchemeKeyedhash(self.tpm_command, self.offset, self.scheme)
        self.offset = self.scheme_details.parse()
        return self.offset   



class TpmsKeyedHashParms(TpmParser):
    """
    Page 132 Part 2 (TPMS_KEYEDHASH_PARMS) Structure
        -- scheme: TPMT_KEYEDHASH_SCHEME+: Indicates the signing method used for a keyedHash signing object. This field also determines the size of the data field for a data object created with TPM2_Create() or TPM2_CreatePrimary().
    """

    def __init__(self, tpm_command, offset, scheme=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.scheme = scheme
        if (self.DEBUG):
            print(" [i] TPMS_KEYEDHASH_PARMS OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_KEYEDHASH_PARMS: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.scheme = TpmtKeyedhashScheme(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.scheme.parse()
        return self.offset   



class TpmsSymcipherParms(TpmParser):
    """
    Page 114 Part 2 (TPMS_SYMCIPHER_PARMS) Structure
        -- sym: TPMT_SYM_DEF_OBJECT: a symmetric block cipher
    """

    def __init__(self, tpm_command, offset, sym=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.sym = sym
        if (self.DEBUG):
            print(" [i] TPMS_SYMCIPHER_PARMS OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_SYMCIPHER_PARMS: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        self.sym = TpmtSymDefObject(self.tpm_command, self.offset, optional_value=False)
        self.offset = self.sym.parse()
        return self.offset   



class TpmsRsaParms(TpmParser):
    """
    Page 133 Part 2 (TPMS_RSA_PARMS) Structure
        -- symmetric: TPMT_SYM_DEF_OBJECT+: for a restricted decryption key, shall be set to a supported symmetric algorithm, key size, and mode. if the key is not a restricted decryption key, this field shall be set to TPM_ALG_NULL.
        -- scheme: TPMT_RSA_SCHEME+ : ...
        -- keyBits:  TPMI_RSA_KEY_BITS: number of bits in the public modulus
        -- exponent: UINT32: the public exponent
    """

    def __init__(self, tpm_command, offset, symmetric=None, scheme=None, key_bits=0, exponent=0):
        TpmParser.__init__(self, tpm_command, offset)
        self.symmetric = symmetric
        self.scheme = scheme
        self.key_bits = key_bits
        self.exponent = exponent
        if (self.DEBUG):
            print(" [i] TPMS_RSA_PARMS OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_RSA_PARMS: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):

        self.symmetric = TpmtSymDefObject(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.symmetric.parse()

        self.scheme = TpmtRsaScheme(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.scheme.parse()

        self.key_bits = self.parse_uint16()

        self.exponent = self.parse_uint32()

        return self.offset



class TpmtEccScheme(TpmParser):
    """
    Page 126 Part 2 TPMT_ECC_SCHEME Structure
        -- scheme: +TPMI_ALG_ECC_SCHEME (TPM_ALG_!ALG.ax, TPM_ALG_!ALG.am, +TPM_ALG_NULL): scheme selector
        -- [scheme]details: TPMU_ASYM_SCHEME: scheme parameters
    """

    def __init__(self, tpm_command, offset, optional_value, scheme=None, scheme_details=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.optional_value = optional_value
        self.scheme = scheme
        self.scheme_details = scheme_details
        if (self.DEBUG):
            print(" [i] TPMT_ECC_SCHEME OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_ECC_SCHEME: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.scheme = TpmAlg(self.tpm_command, self.offset, alg_types=['assymetric','signing','method'], optional_value=self.optional_value)
        self.offset = self.scheme.parse()
        self.scheme_details = TpmuAsymScheme(self.tpm_command, self.offset, self.scheme.tpm_alg)
        self.offset = self.scheme_details.parse()
        return self.offset
           


class TpmEccCurve(TpmParser):
    """
    Page 28 Part 2 TPM_ECC_CURVE (UINT16) Constants <IN/OUT, S>
    """
    TPM_ECC = {0x0000:"TPM_ECC_NONE", 0x0001:"TPM_ECC_NIST_P192", 0x0002:"TPM_ECC_NIST_P224", 0x0003:"TPM_ECC_NIST_P256", 0x0004:"TPM_ECC_NIST_P384", 0x0005:"TPM_ECC_NIST_P521", 0x0010:"TPM_ECC_BN_P256", 0x0011:"TPM_ECC_BN_P638", 0x0020:"TPM_ECC_SM2_P256"}

    def __init__(self, tpm_command, offset, tpm_ecc=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.tpm_ecc = tpm_ecc
        if (self.DEBUG):
            print(" [i] TPM_ECC_CURVE OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM_ECC_CURVE: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        value = self.parse_uint16()
        if value in self.TPM_ECC:
            self.tpm_ecc = self.TPM_ECC[value]
        else:
            self.tpm_ecc = hex(value)
        return self.offset



class TpmuKdfScheme(TpmParser):
    """
    Page 121 Part 2 TPMU_KDF_SCHEME Union <IN/OUT, S>
        'Parameter:Type:Selector'
        -- !ALG.HM: TPMS_SCHEME_!ALG.HM (TPMS_SCHEME_HASH--> TPMI_ALG_HASH --> TPM_ALG_!ALG.H) : TPM_ALG_!ALG.HM
        -- null: : TPM_ALG_NULL
    """

    def __init__(self, tpm_command, offset, selector, enumerated_value=dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.selector = selector
        self.enumerated_value = enumerated_value
        if (self.DEBUG):
            print(" [i] TPMU_KDF_SCHEME OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMU_KDF_SCHEME: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.selector in TpmAlg.tpm_alg_hash.values() and self.selector in TpmAlg.tpm_alg_method.values():
            self.enumerated_value = {'!ALG.HM':TpmAlg(self.tpm_command, self.offset, alg_types=['hash','method'], optional_value=False)}  #TODO: Maybe this is an OR for 'hash' and method regarding resolution
            self.offset = self.enumerated_value['!ALG.HM'].parse()          
        elif self.selector == "TPM_ALG_NULL": 
            self.enumerated_value = {'null':'NULL'}
        return self.offset



class TpmtKdfScheme(TpmParser):
    """
    Page 126 Part 2 TPMT_KDF_SCHEME Structure
        -- scheme: +TPMI_ALG_KDF (TPM_ALG_!ALG.HM, +TPM_ALG_NULL): scheme selector
        -- [scheme]details: TPMU_KDF_SCHEME: scheme parameters
    """

    def __init__(self, tpm_command, offset, optional_value, scheme=None, scheme_details=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.optional_value = optional_value
        self.scheme = scheme
        self.scheme_details = scheme_details
        if (self.DEBUG):
            print(" [i] TPMT_KDF_SCHEME OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_KDF_SCHEME: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.scheme = TpmAlg(self.tpm_command, self.offset, alg_types=['hash','method'], optional_value=self.optional_value)
        self.offset = self.scheme.parse()

        self.scheme_details = TpmuKdfScheme(self.tpm_command, self.offset, self.scheme.tpm_alg)
        self.offset = self.scheme_details.parse()
        return self.offset



class TpmsEccParms(TpmParser):
    """
    Page 134 Part 2 (TPMS_ECC_PARMS) Structure
        -- symmetric: TPMT_SYM_DEF_OBJECT+
        -- scheme: TPMT_ECC_SCHEME+
        -- curveID: TPMI_ECC_CURVE ($ECC_CURVES)
        -- kdf: TPMT_KDF_SCHEME+
    """

    def __init__(self, tpm_command, offset, symmetric=None, scheme=None, curve_id=None, kdf=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.symmetric = symmetric
        self.scheme = scheme
        self.curve_id = curve_id
        self.kdf = kdf
        if (self.DEBUG):
            print(" [i] TPMS_ECC_PARMS OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_ECC_PARMS: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.symmetric = TpmtSymDefObject(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.symmetric.parse()

        self.scheme = TpmtEccScheme(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.scheme.parse()
        
        self.curve_id = TpmEccCurve(self.tpm_command, self.offset)  # TODO: not sure about this
        self.offset = self.curve_id.parse()

        self.kdf = TpmtKdfScheme(self.tpm_command, self.offset, optional_value=True)
        self.offset = self.kdf.parse()
        return self.offset



class TpmuPublicParms(TpmParser):
    """
    Definition of (TPMU_PUBLIC_PARMS) Union <IN/OUT, S>
    Page 134 Part 2
        'Parameter: Type: Selector'
        keyedHashDetail: TPMS_KEYEDHASH_PARMS: TPM_ALG_KEYEDHASH
        symDetail: TPMS_SYMCIPHER_PARMS: TPM_ALG_SYMCIPHER
        rsaDetail: TPMS_RSA_PARMS: TPM_ALG_RSA
        eccDetail: TPMS_ECC_PARMS: TPM_ALG_ECC
        asymDetail: TPMS_ASYM_PARMS: 
    """

    def __init__(self, tpm_command, offset, selector, enumerated_value=dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.selector = selector
        self.enumerated_value = enumerated_value
        if (self.DEBUG):
            print(" [i] TPMU_PUBLIC_PARMS OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMU_PUBLIC_PARMS: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.selector == "TPM_ALG_KEYEDHASH":
            self.enumerated_value = {'keyedHashDetail':TpmsKeyedHashParms(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['keyedHashDetail'].parse()
        elif self.selector == "TPM_ALG_SYMCIPHER":
            self.enumerated_value = {'symDetail':TpmsSymcipherParms(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['symDetail'].parse()
        elif self.selector == "TPM_ALG_RSA":
            self.enumerated_value = {'rsaDetail':TpmsRsaParms(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['rsaDetail'].parse()
        elif self.selector == "TPM_ALG_ECC":
            self.enumerated_value = {'eccDetail':TpmsEccParms(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['eccDetail'].parse()
        # TODO: TPMS_ASYM_PARMS implementation. Dont know how to handle this
        return self.offset



class Tpm2bPublicKeyRsa(TpmParser):
    """
    Page 124 Part 2 (TPM2B_PUBLIC_KEY_RSA) Structure
        -- size: UINT16 : size of the buffer (zero is valid for create)
        -- buffer[size] {: MAX_RSA_KEY_BYTES}: BYTE: Value
    """

    def __init__(self, tpm_command, offset, size=0, buf=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.size = size
        self.buf = buf
        if (self.DEBUG):
            print(" [i] TPM2B_PUBLIC_KEY_RSA OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_PUBLIC_KEY_RSA :\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.size = self.parse_uint16()

        self.buf = self.tpm_command[self.offset:self.offset+self.size]
        if self.buf:
            self.buf = "0x"+self.buf.encode('hex')
        self.offset += self.size

        return self.offset



class Tpm2bEccParameter(TpmParser):
    """
    Page 125 Part 2 (TPM2B_ECC_PARAMETER) Structure
        -- size: UINT16: size of buffer
        -- buffer[size] {::MAX_ECC_KEY_BYTES}: BYTE: the parameter data
    """

    def __init__(self, tpm_command, offset, size=0, buf=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.size = size
        self.buf = buf
        if (self.DEBUG):
            print(" [i] TPM2B_ECC_PARAMETER OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_ECC_PARAMETER :\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.size = self.parse_uint16()
        self.buf = self.tpm_command[self.offset:self.offset+self.size]
        if self.buf:
            self.buf = "0x"+self.buf.encode('hex')
        self.offset += self.size
        return self.offset



class TpmsEccPoint(TpmParser):
    """
    Page 125 Part 2 (TPMS_ECC_POINT) Structure
        -- x: TPM2B_ECC_PARAMETER: X coordinate
        -- y: TPM2B_ECC_PARAMETER: Y coordinate
    """

    def __init__(self, tpm_command, offset, x=None, y=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.x = x
        self.y = y
        if (self.DEBUG):
            print(" [i] TPMS_ECC_POINT OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_ECC_POINT :\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.x = Tpm2bEccParameter(self.tpm_command, self.offset)
        self.offset = self.x.parse()

        self.y = Tpm2bEccParameter(self.tpm_command, self.offset)
        self.offset = self.y.parse()
        return self.offset



class TpmuPublicId(TpmParser):
    """
    Definition of (TPMU_PUBLIC_ID) Union <IN/OUT, S>
    Page 131 Part 2
        'Parameter: Type: Selector'
        keyedHash: TPM2B_DIGEST: TPM_ALG_KEYEDHASH
        sym: TPM2B_DIGEST: TPM_ALG_SYMCIPHER
        rsa: TPM2B_PUBLIC_KEY_RSA: TPM_ALG_RSA
        ecc: TPMS_ECC_POINT: TPM_ALG_ECC
        derive: TPMS_DERIVE: 
    """

    def __init__(self, tpm_command, offset, selector, enumerated_value=dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self.selector = selector
        self.enumerated_value = enumerated_value
        if (self.DEBUG):
            print(" [i] TPMU_PUBLIC_ID OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMU_PUBLIC_ID: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        if self.selector == "TPM_ALG_KEYEDHASH":
            self.enumerated_value = {"keyedHash":Tpm2bDigest(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value["keyedHash"].parse()
            if self.enumerated_value["keyedHash"].buf:
                self.enumerated_value["keyedHash"].buf = "0x"+self.enumerated_value["keyedHash"].buf.encode('hex')
        elif self.selector == "TPM_ALG_SYMCIPHER":
            self.enumerated_value = {"sym":Tpm2bDigest(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value["sym"].parse()
            if self.enumerated_value["sym"].buf:
                self.enumerated_value["sym"].buf = "0x"+self.enumerated_value["sym"].buf.encode('hex')
        elif self.selector == "TPM_ALG_RSA":
            self.enumerated_value = {'rsa':Tpm2bPublicKeyRsa(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value['rsa'].parse()
        elif self.selector == "TPM_ALG_ECC":
            self.enumerated_value = {'ecc':TpmsEccPoint(self.tpm_command, self.offset)}
            self.offset = self.enumerated_value["ecc"].parse()
        # elif TPMS_DERIVE #TODO. Dont know what to do with this
        return self.offset



class TpmtPublic(TpmParser):
    """
    Page 135 Part 2 (TPMT_PUBLIC) Structure
        -- type: TPMI_ALG_PUBLIC (TPM_ALG_!ALG.o): "algorithm" associated with this object
        -- nameAlg: +TPMI_ALG_HASH (TPM_ALG_!ALG.H + NULL) : algorithm used for computing the Name of the object
        -- objectAttributes: TPMA_OBJECT: attributes that, along with type, determine the manipulations of this object
        -- authPolicy: TPM2B_DIGEST: optional policy for using this key. The policy is computed using the nameAlg of the object. (Empty if no authorization policy is present)
        -- [type]parameters: TPMU_PUBLIC_PARMS: the algorithm or structure details
        -- [type]unique: TPMU_PUBLIC_ID: the unique identifier of the structure. For an asymmetric key, this would be the public key. 
    """

    def __init__(self, tpm_command, offset, optional_value, tmtp_public_type=None, nameAlg=None, object_attributes=None, auth_policy=None, type_parameters=None, type_unique=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.optional_value = optional_value
        self.tmtp_public_type = tmtp_public_type
        self.nameAlg = nameAlg
        self.object_attributes = object_attributes
        self.auth_policy = auth_policy
        self.type_parameters = type_parameters
        self.type_unique = type_unique
        if (self.DEBUG):
            print(" [i] TPMT_PUBLIC OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_PUBLIC: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.tmtp_public_type = TpmAlg(self.tpm_command, self.offset, alg_types=['object'], optional_value=False)
        self.offset = self.tmtp_public_type.parse()

        self.nameAlg = TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=self.optional_value)
        self.offset = self.nameAlg.parse()

        self.object_attributes = TpmaObject(self.tpm_command,self.offset)
        self.offset = self.object_attributes.parse()

        self.auth_policy = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.auth_policy.parse()
        if self.auth_policy.buf:
            self.auth_policy.buf = "0x"+self.auth_policy.buf.encode('hex')

        self.type_parameters = TpmuPublicParms(self.tpm_command, self.offset, self.tmtp_public_type.tpm_alg)
        self.offset = self.type_parameters.parse()

        self.type_unique = TpmuPublicId(self.tpm_command,self.offset,self.tmtp_public_type.tpm_alg)
        self.offset = self.type_unique.parse()
        return self.offset



class Tpm2bPrivate(TpmParser):
    """
    Page 138 Part 2 (TPM2B_PRIVATE) Structure <IN/OUT, S>
        -- size: UINT16: size of the private structure
        -- buffer[size] {::sizeof(_PRIVATE)}: BYTE: an encrypted private area
    """
    def __init__(self, tpm_command, offset, size=0, buf=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.size = size
        self.buf = buf
        if (self.DEBUG):
            print(" [i] TPM2B_PRIVATE OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_PRIVATE: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.size = self.parse_uint16()
        self.buf = self.tpm_command[self.offset:self.offset+self.size]
        if self.buf:
            self.buf = "0x"+self.buf.encode('hex')
        self.offset += self.size
        return self.offset



class Tpm2bPublic(TpmParser):
    """
    Page 135 Part 2 (TPM2B_PUBLIC) Structure
        -- size= UINT16: size of publicArea
        -- publicArea: +TPMT_PUBLIC: the public area
    """

    def __init__(self, tpm_command, offset, optional_value, size_equal=0, public_area=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.optional_value = optional_value
        self.size_equal = size_equal
        self.public_area = public_area
        if (self.DEBUG):
            print(" [i] TPM2B_PUBLIC OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_PUBLIC: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.size_equal = self.parse_uint16()
        self.public_area = TpmtPublic(self.tpm_command, self.offset, optional_value=self.optional_value)
        self.offset = self.public_area.parse()
        return self.offset



class Tpm2bData(TpmParser):
    """
    Page 90 Part 2 (TPM2B_DATA) Structure
        -- size: UINT16: size in octets of the buffer field; may be 0
        -- buffer[size]{:sizeof(TPMT_HA)}: BYTE
    """

    def __init__(self, tpm_command, offset, size=0, buf=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.size = size
        self.buf = buf
        if (self.DEBUG):
            print(" [i] TPM2B_DATA OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_DATA:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.size = self.parse_uint16()
        self.buf = self.tpm_command[self.offset:self.offset+self.size]
        self.offset += self.size
        return self.offset



class TpmsPcrSelection(TpmParser):
    """
    Page 94 Part 2 (TPMS_PCR_SELECTION) Structure
        -- hash: TPMI_ALG_HASH (TPM_ALG_!ALG.H): the hash algorithm associated with the selection
        -- sizeofSelect {PCR_SELECT_MIN::}: UINT8: the size in octets of the pcrSelect array
        -- pcrSelect[sizeofSelect] {:PCR_SELECT_MAX}: BYTE: the bit map of selected PCR
    """

    def __init__(self, tpm_command, offset, hash_value=None, size_of_select=0, pcr_select=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.hash_value = hash_value
        self.size_of_select = size_of_select
        self.pcr_select = pcr_select
        if (self.DEBUG):
            print(" [i] TPMS_PCR_SELECTION OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_PCR_SELECTION:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.hash_value = TpmAlg(self.tpm_command, self.offset, alg_types=['hash'], optional_value=False)
        self.offset = self.hash_value.parse()

        self.size_of_select = self.parse_uint8()

        self.pcr_select = self.tpm_command[self.offset:self.size_of_select+self.offset]
        if self.pcr_select:
            self.pcr_select = "0x"+self.pcr_select.encode('hex')
        self.offset += self.size_of_select

        return self.offset



class TpmlPcrSelection(TpmParser):
    """
    Page 102 Part 2 (TPML_PCR_SELECTION) Structure
        -- count: UINT32: number of selection structures. A value of zero is allowed
        -- pcrSelections[count]{:HASH_COUNT}: TPMS_PCR_SELECTION: list of selections

    """

    def __init__(self, tpm_command, offset, count=0, pcr_selections=list()):
        TpmParser.__init__(self, tpm_command, offset)
        self.count = count
        self.pcr_selections = list() #pcr_selections
        if (self.DEBUG):
            print(" [i] TPML_PCR_SELECTION OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPML_PCR_SELECTION:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        # Step 1 parse count
        self.count = self.parse_uint32()

        # Step 2 parse pcr_selections
        for index in range(self.count):
            pcr_selection = TpmsPcrSelection(self.tpm_command, self.offset)
            self.offset = pcr_selection.parse()
            self.pcr_selections.append(pcr_selection)
        return self.offset



class TpmaLocality(TpmParser):
    """
    Page 70 Part 2 (UINT8) TPMA_LOCALITY Bits <IN/OUT>
        -- 0: TPM_LOC_ZERO
        -- 1: TPM_LOC_ONE
        -- 2: TPM_LOC_TWO
        -- 3: TPM_LOC_THREE
        -- 4: TPM_LOC_FOUR
        -- 7:5 Extended: If any of these bits is set, an extended locality is indicated

    """
    tpma_locality_translation = {0:'TPM_LOC_ZERO',1:'TPM_LOC_ONE',2:'TPM_LOC_TWO',3:'TPM_LOC_THREE',4:'TPM_LOC_FOUR',5:'Extended',6:'Extended',7:'Extended'}

    def __init__(self, tpm_command, offset,  tpma_locality=dict()):
        TpmParser.__init__(self, tpm_command, offset)
        self. tpma_locality =  tpma_locality
        if (self.DEBUG):
            print(" [i] TPMA_LOCALITY OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMA_LOCALITY:\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        tpma_locality_byte = self.parse_uint8()
        for bit in range(8):
            if( ( tpma_locality_byte >> bit & 1) == 1):
                self.tpma_locality[self.tpma_locality_translation[bit]] = 'SET'
            else:
                self.tpma_locality[self.tpma_locality_translation[bit]] = 'CLEAR'
        return self.offset



class Tpm2bName(TpmParser):
    """
    Page 93 Part 2 (TPM2B_NAME) Structure
        -- size: UINT16: size of the Name structure
        -- name[size]{:sizeof(TPMU_NAME)}: BYTE: the Name structure
    """

    def __init__(self, tpm_command, offset, size=0, name=''):
        TpmParser.__init__(self, tpm_command, offset)
        self.size = size
        self.name = name
        if (self.DEBUG):
            print(" [i] TPM2B_NAME OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_NAME :\n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.size = self.parse_uint16()
        self.name = self.tpm_command[self.offset:self.offset+self.size]
        if self.name:
            self.name = "0x"+self.name.encode('hex')
        self.offset += self.size
        return self.offset



class TpmsCreationData(TpmParser):
    """
    page 150 part 2 (TPMS_CREATION_DATA) Structure
        -- pcrSelect: TPML_PCR_SELECTION: list indicating the PCR included in pcrDigest
        -- pcrDigest: TPM2B_DIGEST: digest of the selected PCR using nameAlg of the object for which this structure is being created pcrDigest.size shall be zero if the pcrSelect list is empty.
        -- locality: TPMA_LOCALITY: the locality at which the object was created
        -- parentNameAlg: TPM_ALG_ID: nameAlg of the parent
        -- parentName: TPM2B_NAME: Name of the parent at time of creation...
        -- parentQualifiedName: TPM2B_NAME: Qualified Name of the parent at the time of creation. Size is the same as parentName.
        -- outsideInfo: TPM2B_DATA: association with additional information added by the key creator. This will be the contents of the outsideInfo parameter in TPM2_Create() or TPM2_CreatePrimary().
    """

    def __init__(self, tpm_command, offset, pcr_select=None, pcr_digest=None, locality=None, parent_name_alg=None, parent_name=None, parent_qualified_name=None, outside_info=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.pcr_select = pcr_select
        self.pcr_digest = pcr_digest
        self.locality = locality
        self.parent_name_alg = parent_name_alg
        self.parent_name = parent_name
        self.parent_qualified_name = parent_qualified_name
        self.outside_info = outside_info
        if (self.DEBUG):
            print(" [i] TPMS_CREATION_DATA OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMS_CREATION_DATA: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.pcr_select = TpmlPcrSelection(self.tpm_command, self.offset)
        self.offset = self.pcr_select.parse()

        self.pcr_digest = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.pcr_digest.parse()
        if self.pcr_digest.buf:
            self.pcr_digest.buf = "0x"+self.pcr_digest.buf.encode('hex')

        self.locality = TpmaLocality(self.tpm_command, self.offset)
        self.offset = self.locality.parse()

        self.parent_name_alg = TpmAlg(self.tpm_command, self.offset, alg_types=['assymetric','symmetric','hash','signing','anonymous','encryption','method','object'], optional_value=True)  # TODO: not sure about this
        self.offset = self.parent_name_alg.parse() 

        self.parent_name = Tpm2bName(self.tpm_command, self.offset)
        self.offset = self.parent_name.parse()

        self.parent_qualified_name = Tpm2bName(self.tpm_command, self.offset)
        self.offset = self.parent_qualified_name.parse()

        
        self.outside_info = Tpm2bData(self.tpm_command, self.offset)
        self.offset = self.outside_info.parse()
        return self.offset



class Tpm2bCreationData(TpmParser):
    """
    page 150 part 2 (TPM2B_CREATION_DATA) Structure <OUT>
        -- size=: UINT16
        -- creationData: TPMS_CREATION_DATA
    """

    def __init__(self, tpm_command, offset, size_equals=0, creation_data=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.size_equals = size_equals
        self.creation_data = creation_data
        if (self.DEBUG):
            print(" [i] TPM2B_CREATION_DATA OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPM2B_CREATION_DATA: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.size_equals = self.parse_uint16()
        self.creation_data = TpmsCreationData(self.tpm_command, self.offset)
        self.offset = self.creation_data.parse()
        return self.offset



class TpmtTkCreation(TpmParser):
    """
    Page 96 Part 2 (TPMT_TK_CREATION) Structure
        -- tag {TPM_ST_CREATION}: TPM_ST: ticket structure tag
        -- #TPM_RC_TAG: :error returned when tag is not TPM_ST_CREATION
        -- hierarchy: TPMI_RH_HIERARCHY+: the hierarchy containing name
        -- digest: TPM2B_DIGEST: This shall be the HMAC produced using a proof value of hierarchy.
    """

    def __init__(self, tpm_command, offset, tag=None, hierarchy=None, digest=None):
        TpmParser.__init__(self, tpm_command, offset)
        self.tag = tag
        self.hierarchy = hierarchy
        self.digest = digest
        if (self.DEBUG):
            print(" [i] TPMT_TK_CREATION OFFSET:{}".format(self.offset)) #!debug


    def __str__(self):
        return '[i] TPMT_TK_CREATION: \n'+'\n'.join(
            ('\t{} = "{}"'.format(item, self.__dict__[item]) for item in self.__dict__ if item not in ['tpm_command','offset']))


    def parse(self):
        self.tag = TpmSt(self.tpm_command, self.offset)  # This could be a constant value in parsing but just in case
        self.offset = self.tag.parse()

        self.hierarchy = TpmiRhHierarchy(self.tpm_command, self.offset, True)
        self.offset = self.hierarchy.parse()

        self.digest = Tpm2bDigest(self.tpm_command, self.offset)
        self.offset = self.digest.parse()
        if self.digest.buf:
            self.digest.buf = "0x"+self.digest.buf.encode('hex')

        return self.offset


if __name__ == '__main__':
    main()