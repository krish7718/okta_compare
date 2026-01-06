import requests

def _ensure_domain_str(domain_url):
    if not isinstance(domain_url, str):
        raise TypeError(f"Expected domain_url as str, got {type(domain_url).__name__}: {domain_url!r}")
    return domain_url if domain_url.startswith(('http://', 'https://')) else f"https://{domain_url}"

def get_groups(domain_url, api_token):
    """
    Fetch all Okta groups from the given domain using the provided API token.
    Pagination is handled via Okta's Link header.
    """
    headers = {
        'Authorization': f"SSWS {api_token}",
        'Accept': 'application/json'
    }

    groups = []
    domain_url = _ensure_domain_str(domain_url)
    url = domain_url + '/api/v1/groups'

    while url:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print("Error fetching groups:", response.status_code, response.text)
            break

        groups.extend(response.json())

        next_link = response.headers.get('Link')
        if next_link and 'rel=\"next\"' in next_link:
            url = next_link.split(';')[0].strip('<>')
        else:
            url = None

    return groups


def export_groups_to_csv(groups, output_file):
    """
    Export Okta groups into a CSV file.
    Matches the export style used in extract_group_rules.py.
    """
    import csv

    fieldnames = [
        'Group ID',
        'Group Name',
        'Description',
        'Type',
        'Created At',
        'Last Updated At'
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for group in groups:
            writer.writerow({
                'Group ID': group.get('id', ''),
                'Group Name': group.get('profile', {}).get('name', ''),
                'Description': group.get('profile', {}).get('description', ''),
                'Type': group.get('type', ''),
                'Created At': group.get('created', ''),
                'Last Updated At': group.get('lastUpdated', '')
            })


def extract_groups(domain_url, api_token, csv_output_file):
    """
    High-level function:
      → Fetch groups
      → Export to CSV
    """
    groups = get_groups(domain_url, api_token)

    if groups:
        export_groups_to_csv(groups, csv_output_file)
    else:
        print("No groups fetched.")
