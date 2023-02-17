# STARS

TODO: Add picture

**Stars** is a multi-cloud DNS record scanner that aims to help cybersecurity/IT analysts identify dangling CNAME records in their cloud DNS services that could possibly lead to subdomain takeover scenarios.

This is a small tool that uses some of the takeover ideas from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz/) for defensive purposes in cloud environments. For each CNAME domain registered in a cloud environment, the tool generates takeover factors (factors that could indicate a subdomain takeover scenario) and mitigation factors (factors that possibly mitigate that scenario). The factors identified by this tool **should not be taken as definitive proof** of a subdomain takeover scenario on a domain, but rather that a domain should be reviewed.

Subdomain takeovers are complex issues that often happen because of a lack of appropriate processes of management/review in DNS zones, which is a common issue in large corporations. This tool can be used to find possible takeover issues in cloud DNS environments which host multiple zones with large record sets.

# Heuristics

The logic of this tool is described in the following diagram:

TODO: Paste diagram

# Prerequisites

The appropriate CLI from the clouds you intend to scan need to be installed for the libraries to function:

- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- [GCloud CLI](https://cloud.google.com/sdk/docs/install?hl=pt-br)

After that, run the following command to install the Python dependencies before running the tool:

```python
$ pip install -r requirements.txt
```

# Usage

## AWS Route53

```bash
$ aws configure
(Authenticate with your AWS credentials)

$ python stars.py --aws
```

PS. The recommended way of authenticating to AWS is using [AWS IAM Identity Center](https://docs.aws.amazon.com/cli/latest/userguide/sso-using-profile.html) to authenticate using `aws sso login` instead of providing an access key with `aws configure`, but the legacy way is easier to use and more widespread. You can also use [IAM roles](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html) directly if you intend to run the tool from AWS services such as an EC2 attached to a role via an instance profile.

## Azure DNS

```bash
$ az login
(Authenticate with your Azure credentials)

$ python stars.py --azure --subscription <SUBSCRIPTION ID>
```

## Google DNS

```bash
$ gcloud init
$ gcloud auth application-default login
(Authenticate with your GCP credentials and select your project)

$ python stars.py --gcp
```

## File DNS

A CSV file can also be used as input for the scan, if your DNS provider is not yet supported and you have a CSV with your CNAME records.

```python
$ python stars.py --file <FILENAME>
```

## Optional flags
- `--all-records` - Run the checks for all domains in the environment, not just the ones in-scope (those known for subdomain takeover risks).
- `--google-dns` - Use Google DoH for NXDOMAIN checks (by default it uses your local DNS resolver).
- `--colors` or `--no-colors` - Colorize output or disable colors.

# Extending functionality

The `scanners` package can be used in a standalone manner by other modules by importing the scanner classes from it (e.g. `from scanners.awsdns import AWSDNSScanner`), instantiating them and running their `fetch_records` command. The `fetch_records` method of each scanner class is a generator that yields every DNS record in the specified environment in each iteration. Example:

```python
from scanners.awsdns import AWSDNSScanner

scanner = AWSDNSScanner()

for record in scanner.fetch_records():
    print(record)
    """
    "record" is a dict in the following format:
    {
        "ZoneName": "DNS name of the zone",
        "Private": True or False indicating whether the zone is private or not,
        "Type": "Type of the record",
        "Name": "Name of the record",
        "Value": "Value of the record",
        ...other environment-specific values...
    }
    """
```

Other checks against individual cloud DNS records (not just CNAME records) can be implemented using these classes, but since this project is aimed at the specific issue of domain takeover it will be left as future work if anyone is interested in developing other use cases.

# Contributing

Anyone can contribute to the project by opening an issue:
(link here)

# Todo
Some ideas of new features to add that weren't included originally but would be nice to have in the future:

- Option to return the details of the record sets in CSV/JSON format
- Option to only dump the record sets, not performing any analysis
- Option to query a custom nameserver
- Handle authentication / permission errors better
- Implement custom generic class to act as data types for DNS records
- Support for more advanced attributes of DNS records and zones in the scanners
- Improve efficiency by providing an option of doing requests / lookups in parallel
- Option to save results to a file
- Implement a local DB with results from previous executions
- Taking screenshots with a headless browser (maybe)
- Verify whether a domain is public knowledge by scraping with passive tools like Sublist3r

# Domains Scope

If you run the tool without the `--all-records` flag, it will only report results on CNAMEs pointing to domains in the following scope:

| Kind           | Domain                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Azure Services | *.cloudapp.net<br> *.azurewebsites.net<br> *.cloudapp.azure.com<br> *.azurewebsites.net<br> *.blob.core.windows.net<br> *.cloudapp.azure.com<br> *.azure-api.net<br> *.azurehdinsight.net<br> *.azureedge.net<br> *.azurecontainer.io<br> *.database.windows.net<br> *.azuredatalakestore.net<br> *.search.windows.net<br> *.azurecr.io<br> *.redis.cache.windows.net<br> *.azurehdinsight.net<br> *.servicebus.windows.net<br> *.visualstudio.com<br> |
| AWS S3 Buckets | *.s3.amazonaws.com<br> *.s3-website.region.amazonaws.com<br> *.s3.region.amazonaws.com<br> *.s3.dualstack.region.amazonaws.com                                                                                                                                                                                                                                                                                                                         |
| Wordpress      | *.wordpress.com                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Agile CRM      | cname.agilecrm.com                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ReadTheDocs    | readthedocs.io                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Canny.IO       | cname.canny.io                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Shopify        | *.shops.myshopify.com<br> *.myshopify.com                                                                                                                                                                                                                                                                                                                                                                                                              |
| Airee.RU       | cdn.airee.ru                                                                                                                                                                                                                                                                                                                                                                                                                                           |

The idea here is to only run the checks against CNAMEs pointing to services that have been seen in subdomain takeover cases. Most of these domains were hand-picked from the vulnerable services documented at the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz/) project. Feel free to add more domains that could be subject to subdomain takeover to the scope by opening an issue.

# License
TODO: Add License