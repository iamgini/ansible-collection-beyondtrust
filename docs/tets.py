from ansible.plugins.lookup import LookupBase
from ansible.module_utils.six.moves.urllib.parse import urlencode
import requests

class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        # Extract the necessary parameters
        api_url = kwargs.get('api_url')
        client_id = kwargs.get('client_id')
        client_secret = kwargs.get('client_secret')
        secret_list = kwargs.get('secret_list')
        retrieval_type = kwargs.get('retrieval_type', 'SECRET')
        auto_approval = kwargs.get('auto_approval', True)
        request_id = kwargs.get('request_id', None)
        retrieve_password = kwargs.get('retrieve_password', False)
        verify_ca = kwargs.get('verify_ca', True)

        headers = {
            'Authorization': f'Bearer {client_id}:{client_secret}'
        }

        if retrieve_password and request_id:
            # Retrieve password with request_id
            response = requests.get(
                f"{api_url}/Credentials/{request_id}",
                headers=headers,
                verify=verify_ca
            )
            if response.status_code == 200:
                return [response.json().get('password')]
            else:
                raise Exception(f"Failed to retrieve password: {response.status_code} - {response.text}")

        # Create a password view request (Step 1)
        payload = {
            'retrievalType': retrieval_type,
            'secrets': secret_list
        }

        response = requests.post(
            f"{api_url}/Requests",
            headers=headers,
            json=payload,
            verify=verify_ca
        )

        if response.status_code == 200:
            result = response.json()
            request_id = result.get('requestId')
            if not auto_approval:
                # If auto_approval is False, return request_id and exit
                return [request_id]
        else:
            raise Exception(f"Failed to create request: {response.status_code} - {response.text}")

        # Retrieve password after approval (Step 2)
        response = requests.get(
            f"{api_url}/Credentials/{request_id}",
            headers=headers,
            verify=verify_ca
        )

        if response.status_code == 200:
            return [response.json().get('password')]
        else:
            raise Exception(f"Failed to retrieve password: {response.status_code} - {response.text}")
