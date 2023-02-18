class FileDNSScanner():
    def __init__(self, file):
        self.file = file

    def fetch_records(self):
        with open(self.file, 'r') as recordsfile:
            for line in recordsfile:
                zone_name, private_zone, record_type, \
                    record_name, record_value = line.rstrip().split(",")

                yield {
                    'ZoneName': zone_name,
                    'Private': True if private_zone == '1' else False,
                    'Name': record_name,
                    'Type': record_type,
                    'Value': record_value
                }
