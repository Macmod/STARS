from azure.identity import DefaultAzureCredential
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.privatedns import PrivateDnsManagementClient
from azure.mgmt.privatedns.models import PrivateZone
from itertools import chain
from re import search


class AzureDNSScanner():
    def __init__(self, subscription, credentials=DefaultAzureCredential()):
        self.dns_client = DnsManagementClient(credentials, subscription)
        self.private_dns_client = PrivateDnsManagementClient(
            credentials, subscription
        )

    def fetch_rrsets(self):
        public_zones = self.dns_client.zones.list()
        private_zones = self.private_dns_client.private_zones.list()
        zones = chain(public_zones, private_zones)

        for zone in zones:
            zone_name = zone.name
            rg_name = search(r'/resourceGroups/([^/]+)', zone.id).groups(1)[0]
            private_zone = isinstance(zone, PrivateZone)

            if not private_zone:
                rrsets = self.dns_client.record_sets.list_by_dns_zone(
                    rg_name, zone.name
                )
            else:
                rrsets = self.private_dns_client.record_sets.list(
                    rg_name, zone.name
                )

            for rrset in rrsets:
                yield rg_name, zone_name, private_zone, rrset

    def fetch_records(self):
        rrsets_iter = self.fetch_rrsets()

        for rg_name, zone_name, private_zone, rrset in rrsets_iter:
            rrset_name = rrset.name
            records = []

            rrset_type = search(
                r'Microsoft\.Network\/(?:[^\/]+)\/([A-Za-z]+)$',
                rrset.type
            ).groups(1)[0]

            if rrset_type == 'CNAME':
                records = [rrset.cname_record.cname]
            elif rrset_type == 'A':
                records = [record.ipv4_address for record in rrset.a_records]
            elif rrset_type == 'AAAA':
                records = [record.ipv6_address for record in rrset.aaaa_records]
            elif rrset_type == 'MX':
                records = rrset.mx_records
            elif rrset_type == 'PTR':
                records = [record.ptrdname for record in rrset.ptr_records]
            elif rrset_type == 'SOA':
                records = [rrset.soa_record]
            elif rrset_type == 'SRV':
                records = rrset.srv_records
            elif rrset_type == 'TXT':
                records = [record.value for record in rrset.txt_records]

            for record in records:
                yield {
                    'ResourceGroup': rg_name,
                    'ZoneName': zone_name,
                    'Private': private_zone,
                    'Name': rrset_name + f'.{zone_name}',
                    'Type': rrset_type,
                    'Value': record
                }