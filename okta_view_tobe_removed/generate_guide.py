from flask import Flask, make_response, render_template
import pandas as pd
import os
from weasyprint import HTML


generate_guide = Flask(__name__)

pre_rendered_html = None


@generate_guide.route('/')
def home():
    global pre_rendered_html  # Use the global variable

    df_group_rules = pd.read_csv(
        "config_csv_files/configEntityGroupRules.csv")
    # df_policies = pd.read_csv(
    #     "config_csv_files/configEntityPolicies.csv")
    df_applications = pd.read_csv(
        "config_csv_files/configEntityApplications.csv")
    df_network_zones = pd.read_csv(
        "config_csv_files/configEntityNetworkZones.csv")
    df_identity_providers = pd.read_csv(
        "config_csv_files/configEntityIdentityProviders.csv")
    df_org_settings = pd.read_csv(
        "config_csv_files/configEntityOrgSettings.csv")
    df_password_policies = pd.read_csv(
        "config_csv_files/configEntityPasswordPolicies.csv")
    df_authorization_servers = pd.read_csv(
        "config_csv_files/configEntityAuthorizationServers.csv")

    # Choose the specific columns you want for each table.
    # df_group_rules = df_group_rules[['Name', 'Status', 'Expression Value',
    #                                  'Users_Excluded', 'Groups_Excluded', 'Action Assign to Groups']]
    df_group_rules = df_group_rules[['Rule ID', 'Rule Name', 'Status', 'Conditions', 'Actions', 'Created At', 'Last Updated At']]
    # df_policies = df_policies[['ID', 'Name',
    #                            'Description', 'Status', 'Priority']]
    df_network_zones = df_network_zones[[
        'Name', 'Status', 'Gateways', 'Proxies', 'Usage']]
    df_applications = df_applications[['Application Name', 'Okta Internal Name', 'Application Type',
                                       'Username Format', 'Logo', 'Groups', 'Application Settings', 'Features', 'Access Policy Name']]
    df_org_settings = df_org_settings[['Address1', 'Address2', 'City', 'Company Name', 'Country', 'End User Support Help URL', 'Phone Number',
                                       'Postal Code', 'State', 'Support Phone Number', 'Website', 'Subdomain', 'Technical Contact Email', 'Billing Contact Email']]
    df_identity_providers = df_identity_providers[['name', 'type', 'protocol_type', 'protocol_endpoints_sso_url', 'protocol_credentials_trust_issuer', 'protocol_credentials_trust_audience',
                                                   'protocol_credentials_signing_kid', 'status', 'policy_maxClockSkew', 'policy_accountLink_action', 'policy_subject_userNameTemplate_template', 'policy_provisioning_action']]
    df_password_policies = df_password_policies[[
        'ID', 'Status', 'Name', 'Description', 'Priority', 'Provider', 'Complexity Settings', 'Lockout Settings', 'Rules']]

    df_authorization_servers = df_authorization_servers[[
        'ID', 'Name', 'Status', 'Description', 'Audiences', 'Issuer', 'Credentials Rotation Mode']]

    # Convert your DataFrames to HTML tables
    html_group_rules = df_group_rules.to_html(index=False)
    #html_policies = df_policies.to_html(index=False)
    html_network_zones = df_network_zones.to_html(index=False)
    html_org_settings = [df_org_settings.iloc[i].to_frame().to_html(
        header=False, index=True) for i in range(len(df_org_settings))]

    # Convert each entity into a separate HTML table with labels and values
    html_identity_providers = [df_identity_providers.iloc[i].to_frame().to_html(
        header=False, index='True') for i in range(len(df_identity_providers))]
    html_password_policies = [df_password_policies.iloc[i].to_frame().to_html(
        header=True, index='True') for i in range(len(df_password_policies))]
    html_applications = [df_applications.iloc[i].to_frame().to_html(
        header=True, index=['Name', 'Value']) for i in range(len(df_applications))]
    html_authorization_servers = [df_authorization_servers.iloc[i].to_frame().to_html(
        header=False, index='True') for i in range(len(df_authorization_servers))]

    # Pass the HTML data to the templates
    pre_rendered_html = render_template('template.html',
                                        org_settings_data=html_org_settings,
                                        group_rules_data=html_group_rules,
                                        #policies_data=html_policies,
                                        network_zones_data=html_network_zones,
                                        authorization_servers_data=html_authorization_servers,
                                        identity_providers_data=html_identity_providers,
                                        password_policies_data=html_password_policies,
                                        applications_data=html_applications)

    return pre_rendered_html


@generate_guide.route('/download_pdf')
def download_pdf():
    global pre_rendered_html

    # Create a PDF using WeasyPrint
    pdf = HTML(string=pre_rendered_html).write_pdf()

    # Create a response
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=Okta-Configuration-Guide.pdf'

    return response


if __name__ == '__main__':
    generate_guide.run(debug=True)
