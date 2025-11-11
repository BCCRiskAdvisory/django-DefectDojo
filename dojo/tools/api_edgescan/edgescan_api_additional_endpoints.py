import requests
from django.conf import settings


class EdgescanAPIAdditionalEndpoints:
    def request_vlnerability_retest(self, vulnerability_id):
        """
        Calls the Edgescan external API to perform a vulnerability retest.

        Payload:
            "vulnerability_ids" - array containing the ids of the vlnerabilities to be retested

        Notes:
            - This function is written as a mixin and included in api_edgescan/api_client.py.
            - Keeps all business logic in one place, reducing merge conflicts in api_client.py.

        """
        url = f"{self.url}/api/v1/vulnerabilities/retest.json"
        payload = {"vulnerability_ids": [vulnerability_id]}
        response = requests.post(
            url=url,
            headers=self.get_headers(),
            proxies=self.get_proxies(),
            timeout=settings.REQUESTS_TIMEOUT,
            json=payload,
        )
        return response.json()
