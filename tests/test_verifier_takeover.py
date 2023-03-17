import pytest
from unittest.mock import patch
from verifiers.takeover import TakeoverVerifier

@patch('verifiers.takeover.has_azure_verification_txt')
@patch('verifiers.takeover.response_body')
@patch('verifiers.takeover.status_code')
@patch('verifiers.takeover.resolve_multi')
def test_takeover_factors_notfound(m1, m2, m3, m4):
    m1.return_value = ['127.0.0.1']
    m2.return_value = 404
    m3.return_value = 'Blah'
    m4.return_value = False

    records = [
        {
            'Name': 'www.test1.com.',
            'Type': 'CNAME',
            'Value': 'shops.myshopify.com',
            'Private': False
        },
        {
            'Name': 'www.test2.com.',
            'Type': 'CNAME',
            'Value': 'another.site.blah.com',
            'Private': False
        },
        {
            'Name': 'www.test3.com.',
            'Type': 'A',
            'Value': '10.0.0.3',
            'Private': False
        },
    ]

    takeover_verifier = TakeoverVerifier(records)

    results = list(takeover_verifier.get_takeover_factors())
    assert len(results) == 1

    result = results[0]

    assert result[0]['Name'] == 'www.test1.com'
    assert result[1] == {'WEB_NOTFOUND'}
    assert result[2] == set()

@patch('verifiers.takeover.has_azure_verification_txt')
@patch('verifiers.takeover.response_body')
@patch('verifiers.takeover.status_code')
@patch('verifiers.takeover.resolve_multi')
def test_takeover_factors_fingerprint(m1, m2, m3, m4):
    m1.return_value = ['127.0.0.1']
    m2.return_value = 200
    m3.return_value = 'Not Found'
    m4.return_value = False

    records = [
        {
            'Name': 'www.test1.com.',
            'Type': 'CNAME',
            'Value': 'shops.myshopify.com',
            'Private': False
        },
        {
            'Name': 'www.test2.com.',
            'Type': 'CNAME',
            'Value': 'another.site.blah.com',
            'Private': False
        },
        {
            'Name': 'www.test3.com.',
            'Type': 'A',
            'Value': '10.0.0.3',
            'Private': False
        },
    ]

    takeover_verifier = TakeoverVerifier(records)

    results = list(takeover_verifier.get_takeover_factors())
    assert len(results) == 1

    result = results[0]

    assert result[0]['Name'] == 'www.test1.com'
    assert result[1] == {'WEB_FINGERPRINT'}
    assert result[2] == set()

@patch('verifiers.takeover.has_azure_verification_txt')
@patch('verifiers.takeover.response_body')
@patch('verifiers.takeover.status_code')
@patch('verifiers.takeover.resolve_multi')
def test_takeover_factors_nxdomain(m1, m2, m3, m4):
    m1.return_value = False
    m2.return_value = None
    m3.return_value = None
    m4.return_value = False
    records = [
        {
            'Name': 'www.test1.com.',
            'Type': 'CNAME',
            'Value': 'shops.myshopify.com',
            'Private': False
        },
        {
            'Name': 'www.test3.com.',
            'Type': 'A',
            'Value': '10.0.0.3',
            'Private': False
        },
    ]

    takeover_verifier = TakeoverVerifier(records)

    results = list(takeover_verifier.get_takeover_factors())
    assert len(results) == 1

    result = results[0]

    assert result[0]['Name'] == 'www.test1.com'
    assert result[1] == {'DNS_NXDOMAIN'}
    assert result[2] == set()


@patch('verifiers.takeover.has_azure_verification_txt')
@patch('verifiers.takeover.response_body')
@patch('verifiers.takeover.status_code')
@patch('verifiers.takeover.resolve_multi')
def test_mitigation_factors(m1, m2, m3, m4):
    m1.return_value = ['127.0.0.1']
    m2.return_value = 200
    m3.return_value = 'Blahblah'
    m4.return_value = True
    records = [
        {
            'Name': 'www.test1.com.',
            'Type': 'CNAME',
            'Value': 'shops.myshopify.com',
            'Private': True
        },
        {
            'Name': 'www.test3.com.',
            'Type': 'A',
            'Value': '10.0.0.3',
            'Private': False
        },
    ]

    takeover_verifier = TakeoverVerifier(records)

    results = list(takeover_verifier.get_takeover_factors())
    assert len(results) == 1

    result = results[0]

    assert result[0]['Name'] == 'www.test1.com'
    assert result[1] == set()
    assert result[2] == {'AZURE_VERIFICATION_TXT', 'PRIVATE_ZONE'}

