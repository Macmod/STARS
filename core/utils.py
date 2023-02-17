import requests
import dns.resolver


def resolve_google(name, type='A'):
    answer_obj = False
    try:
        response = requests.get(
            f'https://dns.google/resolve?name={name}&type={type}'
        )
        answer_obj = response.json()
    except Exception as e:
        print(f'[-] DNS Exception ("{e}")')

    return answer_obj


def resolve_multi(name, type='A', use_google_dns=False):
    records = []
    try:
        if use_google_dns:
            answer_obj = resolve_google(name, type)
            if 'Answer' in answer_obj:
                answer_list = answer_obj['Answer']
                records = [r['data'] for r in answer_list]
        else:
            answer_obj = dns.resolver.resolve(name, type)
            records = [str(answer) for answer in answer_obj]
    except Exception:
        pass

    return records


def status_code(domain, schema='https'):
    code = -1
    try:
        response = requests.get(f'{schema}://{domain}', verify=False)
        code = response.status_code
    except Exception:
        pass

    return code


def response_body(domain, schema='https'):
    response = ''
    try:
        response_obj = requests.get(f'{schema}://{domain}', verify=False)
        response = response_obj.text
    except Exception:
        pass

    return response


def has_azure_verification_txt(domain, use_google_dns=False):
    azure_verification_txt = resolve_multi(f'asuid.{domain}', type='TXT')
    return azure_verification_txt
