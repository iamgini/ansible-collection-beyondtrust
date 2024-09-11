# (c) 2023 BeyonTrust Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
name: secrets_safe_lookup
author: BeyondTrust
version_added: "1.0.0"
short_description: Retrieve ASCII secrets from Secrets Safe.
description:
    - Retrieve ASCII secrets and managed account passwords from BeyondTrust Pasword safe 23.1 or greater.
options:
    api_url:
        description: BeyondTrust Pasword Safe API URL.
        type: string
        required: True
    retrieval_type:
        description: Type of secret to retrieve (use MANAGED_ACCOUNT or SECRET)
        type: string
        required: True
    client_id:
        description: API OAuth Client ID.
        type: string.
        required: True
    client_secret:
        description: API OAuth Client Secret.
        type: string.
        required: True
    secret_list:
        description: List of secrets (path/title,path/title) or managed accounts (ms/ma,ms/ma) to be retrieved, separated by comma.
        type: string
        required: True
    certificate_path:
        description: Password Safe API pfx Certificate Path. For use when authenticating using a Client Certificate.
        type: string
        required: False
    certificate_password:
        description: Password Safe API pfx Certificate Password. For use when authenticating using a Client Certificate.
        type: string
        required: False
    verify_ca:
        description: Indicates whether to verify the certificate authority on the Secrets Safe instance.
        type: boolean 
        default: True
        required: False
"""

EXAMPLES = """
- vars:
    apiURL: "{{ lookup('ansible.builtin.env', 'PASSWORD_SAFE_API_URL') }}"

    clientIdFromEnvVar: "{{ lookup('ansible.builtin.env', 'PASSWORD_SAFE_CLIENT_ID') }}"
    secretFromEnvVar: "{{ lookup('ansible.builtin.env', 'PASSWORD_SAFE_CLIENT_SECRET') }}"

    certificatePasswordFromEnVar:  "{{ lookup('ansible.builtin.env', 'CERTIFICATE_PASSWORD') }}"
    certificatePath: "<path>/ClientCertificate.pfx"

    secretManagedAccounts: "fake_system/fake_ managed_account,fake_system/fake_managed_account01"
    gotManagedAccount: "{{lookup('beyondTrust.secrets_safe.secrets_safe_lookup', api_url=apiURL, retrieval_type='MANAGED_ACCOUNT', client_id=clientIdFromEnvVar, client_secret=secretFromEnvVar, secret_list=secretManagedAccounts, certificate_path=certificatePath, certificate_password=certificatePasswordFromEnVar, wantlist=False)}}"

    secretList: "fake_grp/credential,fake_grp/file"
    gotSecrets: "{{lookup('beyondTrust.secrets_safe.secrets_safe_lookup', api_url=apiURL, retrieval_type='SECRET', client_id=clientIdFromEnvVar, client_secret=secretFromEnvVar, secret_list=secretList, certificate_path=certificatePath, certificate_password=certificatePasswordFromEnVar, wantlist=False, verify_ca=True)}}"
"""

RETURN = """
  _list:
    description: list of retrieved  secret(s) in the requested order.
    type: list
    elements: str
"""

from ansible.errors import AnsibleOptionsError, AnsibleLookupError, AnsibleAuthenticationFailure
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display
import requests
import json
import contextlib
import OpenSSL.crypto
import tempfile

display = Display()

from retry_requests import retry
from requests import Session

req = retry(requests.Session(), retries=3, backoff_factor=0.2)

config = {}

SIGNOUT_MESSAGE = "Error trying to sign out!"

class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        
        display.v("Starting workflow")       
        self.set_options(var_options=variables, direct=kwargs)
        
        config['url'] = self.validate_parameters(kwargs, 'api_url', 'Missing api_url parameter')
        retrieval_type = self.validate_parameters(kwargs, 'retrieval_type', 'missing retrieval_type parameter')
        client_id = self.validate_parameters(kwargs, 'client_id', 'Missing client_id parameter')
        client_secret = self.validate_parameters(kwargs, 'client_secret', 'Missing client_secret parameter')
        secret_list = self.validate_parameters(kwargs, 'secret_list', 'Missing secret_list parameter')
        
        certificate_path = kwargs['certificate_path'] if 'certificate_path' in kwargs and kwargs['certificate_path'].strip() else ""
        certificate_password = kwargs['certificate_password'] if 'certificate_password' in kwargs and kwargs['certificate_password'].strip() else ""
        
        verify_ca = kwargs['verify_ca'] if 'verify_ca' in kwargs else True
        separator = kwargs['separator'] if 'separator' in kwargs and kwargs['separator'].strip() else "/"
        
        display.v(f"retrieval_type: {retrieval_type}")
        display.vv(f"api_url: {config['url']}")
        display.vv(f"secret_list: {secret_list}")
        display.vv(f"certificate_path: {certificate_path}")
        display.vv(f"verify_ca: {verify_ca}")
        
        paths = secret_list.split(",")
        
        oauth_response = oauth(client_id, client_secret, verify_ca)
        
        if oauth_response.status_code != 200:
            raise AnsibleAuthenticationFailure(f"Error getting token, message: {oauth_response.text}, statuscode: {oauth_response.status_code}")
                        
        token_object=json.loads(oauth_response.text)
        token = token_object['access_token']

        req.verify = verify_ca
    
        response = []
    
        if token:
            sign_app_in_response = sign_app_in(token, certificate_path, certificate_password)
            
            if sign_app_in_response.status_code != 200:
                raise AnsibleAuthenticationFailure(f"Error sign app in, message: {sign_app_in_response.text}, statuscode: {sign_app_in_response.status_code}")

            # Clear token variable from memory
            del token

            if retrieval_type.upper() == "MANAGED_ACCOUNT":
                response = self.managed_account_flow(paths)
                    
            elif retrieval_type.upper() == "SECRET":
                retrieved_secrets = self.secrets_by_path_flow(paths, separator)
                response.extend(retrieved_secrets)
            
            else:
                raise AnsibleOptionsError(f"Invalid Retrieval_Type: {retrieval_type}")

        display.v("Ending workflow")
        return response


    def validate_parameters(self, parameters, parameter_key, error_message):
        if parameter_key in parameters and parameters[parameter_key].strip() != "":
            return parameters[parameter_key].strip() 
        else:
            raise AnsibleOptionsError(error_message)


    def managed_account_flow(self, paths):
        response = []
        
        for path in paths:
                
            display.vv(f"**************** managed account path: {path} ****************")
            data = path.split("/")
            
            if len(data) != 2:
                raise AnsibleLookupError(f"Invalid managed account path: {path}. Use a forward slash as a delimiter: system_name/managed_account_name")
            
            system_name = data[0]
            managed_account_name = data[1]
            
            manage_account_response = get_managed_accounts(system_name, managed_account_name)
            
            if manage_account_response.status_code != 200:
                raise AnsibleLookupError(f"Error getting the manage account, message: {manage_account_response.text}, statuscode: {manage_account_response.status_code}, system name: {system_name}, managed account name: {managed_account_name}")
            
            manage_account = manage_account_response.json()
            
            display.vv("Managed account info retrieved!")
            
            create_request_response = create_request(
                manage_account['SystemId'], manage_account['AccountId'])
            
            if create_request_response.status_code not in (200, 201):
                if not sign_app_out():
                    display.error(SIGNOUT_MESSAGE)
                raise AnsibleLookupError(f"Error creating the request, message: {create_request_response.text}, statuscode: {create_request_response.status_code}")

            request_id = create_request_response.json()

            display.vvv(f"Request id retrieved: {'*' * len(str(request_id))}")
            
            if not request_id:
                raise AnsibleLookupError("Request Id not found")
            
            get_credential_by_request_id_response = get_credential_by_request_id(request_id)
            
            if get_credential_by_request_id_response.status_code != 200:
                if not sign_app_out():
                    display.error(SIGNOUT_MESSAGE)
                raise AnsibleLookupError(f"Error getting the credential by request_id, message: {get_credential_by_request_id_response.text}, statuscode: {get_credential_by_request_id_response.status_code}")

            credential = get_credential_by_request_id_response.text

            response.append(credential)
            
            display.vvv("Credential was retrieved succesfully!")
            
            request_check_in_response = request_check_in(request_id)

            if request_check_in_response.status_code != 204:
                if not sign_app_out():
                    display.error(SIGNOUT_MESSAGE)
                raise AnsibleLookupError(f"Error checking in the request, message: {request_check_in_response.text}, statuscode: {request_check_in_response.status_code}")
                
            display.vvv("Checkin done!")
        return response


    def secrets_by_path_flow(self, paths, separator):
        response = []
        for path in paths:
            display.vv(f"**************** secret path: {path} *****************")

            data = path.split(separator)
            
            if len(data) < 2:
                raise AnsibleLookupError(f"Invalid secret path: {path}, check your path and title separator")

            folder_path = data[:-1]
            title = data[-1]
            
            secret_response = get_secret_by_path(separator.join(folder_path), title, separator)
    
            if secret_response.status_code != 200:
                if not sign_app_out():
                    display.errordisplay.error(SIGNOUT_MESSAGE)
                raise AnsibleLookupError(f"Error getting secret by path, message: {secret_response.text}, statuscode: {secret_response.status_code}")
            
            secret = secret_response.json()

            if secret:
                display.vv(f"Secret type: {secret[0]['SecretType']}")
                
                if secret[0]['SecretType'] == "File":
                    display.vvv("Getting secret by file")
                    file_response = get_file_by_id(secret[0]['Id'])
                    
                    if file_response.status_code != 200:
                        if not sign_app_out():
                            display.error(SIGNOUT_MESSAGE)
                        raise AnsibleLookupError(f"Error getting file by id, message: {file_response.text}, statuscode: {file_response.status_code}")

                    response.append(file_response.text)
                else:
                    response.append(secret[0]['Password'])

                display.vvv("Secret file was retrieved!")
            else:
                raise AnsibleLookupError("Secret was not found")
        
        return response


def oauth(client_id, secret, verify_ca=True):
    """
    Get API Token
    Arguments:
        Client Id
        Secret
    Returns:
        Token
    """
    
    url = config['url'] + "/Auth/connect/token"
    header = {'Content-Type' : 'application/x-www-form-urlencoded'}
    display.vvv(f"Calling oauth endpoint: {url}")
    auth_info = {
      'client_id' : client_id,
      'client_secret' : secret,
      'grant_type' : 'client_credentials'
    } 

    response = requests.post(url, auth_info, header, verify=verify_ca)
    return response

@contextlib.contextmanager
def pfx_to_pem(pfx_path, pfx_password):
    """
    Decrypts the .pfx file to be used with requests
    Arguments:
        PFX path
        PFX Password
    Returns:
        PEM file name
    """

    try:
        with tempfile.NamedTemporaryFile(suffix='.pem') as t_pem:
            f_pem = open(t_pem.name, 'wb')
            pfx = open(pfx_path, 'rb').read()
            p12 = OpenSSL.crypto.load_pkcs12(pfx, pfx_password)
            f_pem.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, p12.get_privatekey()))
            f_pem.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, p12.get_certificate()))
            ca = p12.get_ca_certificates()
            if ca is not None:
                for cert in ca:
                    f_pem.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            f_pem.close()
            yield t_pem.name
            
    except FileNotFoundError as e:
        raise AnsibleLookupError(f"Certificate not found: {e}")
    except Exception as e:
        raise AnsibleLookupError(f"Missing certificate password or incorrect certificate password: {e}")

        
def send_post_sign_app_in(url, cert, token):
    """
    Send Post request to Sign app in service
    Arguments:
    Returns:
        Service URL
        Certificate
    """
           
    headers = {'Authorization': f'Bearer {token}'}
    display.vvv(f"Calling sign_app_in endpoint: {url}")
    response = req.post(url, headers=headers, cert=cert)
    return response

def sign_app_in(token, certificate_path, certificate_password):
    """
    Sign in to Secret safe API
    Arguments:
    Returns:
        logged user
    """

    url = f"{config['url']}/Auth/SignAppIn/"
    if certificate_path:
        with pfx_to_pem(certificate_path, certificate_password) as cert:
            return send_post_sign_app_in(url, cert, token)

    else:
        return send_post_sign_app_in(url, None, token)

def sign_app_out():
    """
    Sign out to Secret safe API
    Arguments:
    Returns:
        Status of the action
    """
    url = f"{config['url']}/Auth/Signout"
    display.vvv(f"Calling sign_app_out endpoint: {url}")
    
    # Connection : close - tells the connection pool to close the connection.
    response = req.post(url, headers={'Connection':'close'})
    if response.status_code == 200:
        return True
    
    return False


####################################################################### Managed account Flow ############################################################
def get_managed_accounts(system_name, account_name):
    """
    Get manage accounts by system name and account name
    Arguments:
        Secret id
    Returns:
        Managed Account object
    """
    url = f"{config['url']}/ManagedAccounts?systemName={system_name}&accountName={account_name}"
    display.vvv(f"Calling get_managed_accounts endpoint {url}")
    response = req.get(url)
    return response


def create_request(system_id, account_id):
    """
    Create request by system id and account id
    Arguments:
        System id, Account id
    Returns:
        Request id
    """
    payload = {
        "SystemID": system_id,
        "AccountID": account_id,
        "DurationMinutes": 5,
        "Reason": "Ansible Integration",
        "ConflictOption": "reuse"
    }

    url = f"{config['url']}/Requests"
    display.vvv(f"Calling create_request endpoint: {url}")
    response = req.post(url, json=payload)
    return response


def get_credential_by_request_id(request_id):
    """
    Get Credential by request id
    Arguments:
        Request id
    Returns:
        Credential info
    """
    
    url = f"{config['url']}/Credentials/{request_id}"
    print_url = f"{config['url']}/Credentials/{'*' * len(str(request_id))}"

    display.vvv(f"Calling get_credential_by_request_id endpoint: {print_url}")
    response = req.get(url)
    return response
    

def request_check_in(request_id):
    """
    Expire request
    Arguments:
        Request id
    Returns:
        Informative text
    """
    url = f"{config['url']}/Requests/{request_id}/checkin"
    print_url = f"{config['url']}/Requests/{'*' * len(str(request_id))}/checkin"

    display.vvv(f"Calling request_check_in endpoint: {print_url}")
    response = req.put(url, json={})
    return response

####################################################################### Secret Flow ############################################################
def get_secret_by_path(path, title, separator, send_title=True):
    """
    Get secrets by path and title
    Arguments:
        Secret Path
        Secret Title
    Returns:
        Secret 
    """
    url = f"{config['url']}/secrets-safe/secrets?path={path}&separator={separator}"

    if send_title:
        url = f"{config['url']}/secrets-safe/secrets?title={title}&path={path}&separator={separator}"

    display.vvv(f"Calling get_secret_by_path endpoint: {url}")

    response = req.get(url)
    return response


def get_file_by_id(secret_id):
    """
    Get a File secret by File id
    Arguments:
        secret id
    Returns:
        File secret text
    """
    url = f"{config['url']}/secrets-safe/secrets/{secret_id}/file/download"
    display.vvv(f"Calling get_file_by_id endpoint {url}")
    response = req.get(url)
    return response