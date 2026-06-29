from urllib.parse import urlencode
import requests


class KeycloakClientInfoFetcher:
    def __init__(
        self,
        keycloak_url: str,
        username: str,
        client_id: str,
        password: str,
        clients_realm: str,
        token_realm: str = "master",
    ):
        self.base_url = keycloak_url.rstrip("/")
        self.username = username
        self.client_id = client_id
        self.password = password
        self.token_realm = token_realm
        self.clients_realm = clients_realm

    def get_client_info(self) -> list[dict]:
        access_token = self._get_access_token()
        url = f"{self.base_url}/admin/realms/{self.clients_realm}/clients"
        print(f"Fetching client info from: {url} with access token: {access_token[:10]}...")  # Print only the first 10 characters for security

        clients_response = requests.get(
            url,
            headers={"Authorization": f"Bearer {access_token}"},
            params={"clientId": self.client_id},
            timeout=30,
        )
        clients_response.raise_for_status()
        return clients_response.json()

    def _get_access_token(self) -> str:

        data = urlencode(
            {
                "client_id": self.client_id,
                "username": self.username,
                "grant_type": "password",
                "password": self.password,
            }
        )

        token_response = requests.post(
            f"{self.base_url}/realms/{self.token_realm}/protocol/openid-connect/token",
            headers={"content-type": "application/x-www-form-urlencoded"},
            data=data,
            timeout=30,
        )
        token_response.raise_for_status()

        response_json = token_response.json()

        # TODO: remove logging before merge!
        print(f"Retrieved: {response_json}")

        access_token = response_json.get("access_token")

        if not access_token:
            raise ValueError("access_token was not returned by Keycloak token endpoint")
        if len(access_token) < 10:  # Assuming a valid token should be longer than 10 characters
            raise ValueError("access_token is masked and not valid")

        return access_token
