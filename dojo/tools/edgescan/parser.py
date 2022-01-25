from dojo.models import Endpoint, Finding
from urlparse import urlparse
import json
import re


ES_SEVERITIES = {1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}


class EdgescanParser(object):
    def __init__(self, filename, test):
        self.items = self.get_findings(filename, test)

    def get_findings(self, file, test):
        if file:
            try:
                data = file.read()
                try:
                    deserialized = json.loads(str(data, "utf-8"))
                except:
                    deserialized = json.loads(data)

                return self.process_vulnerabilities(test, deserialized)
            except Exception as e:
                raise Exception("Invalid format: {}".format(e))
        else:
            raise Exception("Invalid file")

    def process_vulnerabilities(self, test, vulnerabilities):
        findings = []

        for vulnerability in vulnerabilities:
            findings.append(make_finding(test, vulnerability))

        return findings

def make_finding(test, vulnerability):
    finding = Finding(test=test)
    finding.title = vulnerability["name"]
    finding.date = vulnerability["date_opened"][:10]
    if vulnerability["cwes"]:
        finding.cwe = int(vulnerability["cwes"][0][4:])
    finding.url = vulnerability["location"]
    finding.severity = ES_SEVERITIES[vulnerability["severity"]]
    finding.description = vulnerability["description"]
    finding.mitigation = vulnerability["remediation"]
    # finding.impact = 
    # finding.references = 
    finding.is_template = False
    finding.active = True
    finding.verified = True
    finding.false_p = False
    finding.duplicate = False
    finding.out_of_scope = False
    # finding.thread_id = 
    # finding.mitigated = 
    # finding.mitigated_by = 
    # finding.reporter = 
    # finding.notes = 
    finding.numerical_severity = Finding.get_numerical_severity(ES_SEVERITIES[vulnerability["severity"]])
    # finding.last_reviewed = 
    # finding.last_reviewed_by = 


    finding.unsaved_endpoints = list()
    endpoint = endpoint_from_uri(test, vulnerability["location"])
    finding.unsaved_endpoints.append(endpoint)

    return finding

def endpoint_from_uri(test, uri):
    try:
        url = urlparse(uri)
    except Exception as e:
        raise Exception('Invalid URL format: {}'.format(e))

    rhost = re.search(
        "(http|https|ftp)\://([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&amp;%\$\-]+)*@)*((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|localhost|([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.(com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|[a-zA-Z]{2}))[\:]*([0-9]+)*([/]*($|[a-zA-Z0-9\.\,\?\'\\\+&amp;%\$#\=~_\-]+)).*?$",
        uri)
    
    port = "80"
    if url.scheme == 'https':
        port = "443"
    if rhost and rhost.group(11) is not None:
        port = str(rhost.group(11))

    try:
        dupe_endpoint = Endpoint.objects.get(protocol=url.scheme,
                                             host=url.netloc + (":" + port) if port is not None else "",
                                             path=url.path,
                                             query=url.query,
                                             fragment=url.fragment,
                                             product=test.engagement.product)
    except:
        dupe_endpoint = None

    if not dupe_endpoint:
        endpoint = Endpoint(
            protocol=url.scheme,
            host=url.netloc + (":" + port) if port is not None else "",
            path=url.path,
            query=url.query,
            fragment=url.fragment,
            product=test.engagement.product
        )
    else:
        endpoint = dupe_endpoint

    return endpoint
