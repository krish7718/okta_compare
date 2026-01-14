import requests
import csv
import configparser

# Load variables from config file
config = configparser.ConfigParser()
config.read('config.ini')

okta_api_token = config.get('okta', 'okta_api_token')
okta_domain_url = config.get('okta', 'okta_domain_url')

def get_mfa_enrollment_policies():
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }
    url = f"{okta_domain_url}/api/v1/policies?type=MFA_ENROLL"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print("Error fetching MFA enrollment policies:", response.status_code)
        return []

def get_policy_rules(policy_id):
    headers = {
        'Authorization': f"SSWS {okta_api_token}",
        'Accept': 'application/json'
    }
    url = f"{okta_domain_url}/api/v1/policies/{policy_id}/rules"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching rules for policy {policy_id}:", response.status_code)
        return []

def export_mfa_policies_to_csv(policies, output_file):
    fieldnames = ['ID', 'Status', 'Name', 'Priority', 'Conditions', 'Settings']
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for policy in policies:
            writer.writerow({
                'ID': policy['id'],
                'Status': policy['status'],
                'Name': policy['name'],
                'Priority': policy.get('priority', ''),
                'Conditions': policy.get('conditions', {}),
                'Settings': policy.get('settings', {})
            })

def export_mfa_policies_rules_to_csv(policies, output_file):
    fieldnames = [
        'policy_id', 'policy_name', 'rule_id', 'rule_name', 'status', 'priority',
        'conditions_people', 'conditions_network', 'conditions_authcontext',
        'conditions_risk', 'conditions_riskScore', 'conditions_identityprovider', 'actions'
    ]
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for policy in policies:
            policy_id = policy['id']
            policy_name = policy['name']
            rules = get_policy_rules(policy_id)
            
            for rule in rules:
                conditions = rule.get('conditions') or {}
                
                writer.writerow({
                    'policy_id': policy_id,
                    'policy_name': policy_name,
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'status': rule['status'],
                    'priority': rule.get('priority', ''),
                    'conditions_people': conditions.get('people', {}),
                    'conditions_network': conditions.get('network', {}),
                    'conditions_authcontext': conditions.get('authContext', {}),
                    'conditions_risk': conditions.get('risk', {}),
                    'conditions_riskScore': conditions.get('riskScore', {}),
                    'conditions_identityprovider': conditions.get('identityProvider', {}),
                    'actions': rule.get('actions', {})
                })

def extract_mfa_policies(csv_output_file):
    policies = get_mfa_enrollment_policies()
    
    if policies:
        export_mfa_policies_to_csv(policies, csv_output_file)
        csv_output_file_rules = csv_output_file.replace(".csv", "_rules.csv")
        export_mfa_policies_rules_to_csv(policies, csv_output_file_rules)