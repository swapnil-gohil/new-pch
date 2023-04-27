import os
from azure.identity import ClientSecretCredential
from azure.storage.blob import BlobServiceClient, RetentionPolicy
from azure.keyvault.secrets import SecretClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import AccessTier, Bypass, DefaultAction, Encryption, EncryptionServices, EncryptionService, IPRule, KeyType, Kind, MinimumTlsVersion, NetworkRuleSet, StorageAccountCreateParameters, Sku, SkuName, VirtualNetworkRule

CLIENT_ID=str(os.getenv('CLIENT_ID'))
CLIENT_SECRET=str(os.getenv('CLIENT_SECRET'))
CONTAINER_NAME='documents'
KEY_VAULT_URL=str(os.getenv('KEY_VAULT_URL'))
REGION=str(os.getenv('REGION'))
RESOURCE_GROUP_NAME=str(os.getenv('RESOURCE_GROUP_NAME'))
STORAGE_ACCOUNT_ALLOWED_IPS=str((os.getenv('STORAGE_ACCOUNT_ALLOWED_IPS')))
SUBSCRIPTION_ID=str(os.getenv('SUBSCRIPTION_ID'))
TENANT_ID=str(os.getenv('TENANT_ID'))
VNET_ID=str(os.getenv('VNET_ID'))


def get_credentials():
    credentials = ClientSecretCredential(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tenant_id=TENANT_ID)
    return credentials


def key_vault_secret_client():
    client = SecretClient(KEY_VAULT_URL, get_credentials())
    return client


# def create_secret(server_name: str, administrator_login_password):
#     secret_client = key_vault_secret_client()
#     secret_client.set_secret(name=server_name + '-admin-username', value=ADMINISTRATOR_LOGIN_USERNAME, enabled=True, tags={'resource': 'mssql-server', 'server-name': server_name, 'type': 'admin-username', 'managed-by': 'python', 'infrastructure': 'attorney-onboarding'})
#     secret_client.set_secret(name=server_name + '-admin-password', value=administrator_login_password, enabled=True, tags={'resource': 'mssql-server', 'server-name': server_name, 'type': 'admin-password', 'managed-by': 'python', 'infrastructure': 'attorney-onboarding'})
#     print(f'Created - Secret for `{server_name}` SQL server.')


def create_storage_account(storage_account_name: str):
    storage_account_client = StorageManagementClient(get_credentials(), SUBSCRIPTION_ID)
    
    ip_rules = []
    allowed_ips = STORAGE_ACCOUNT_ALLOWED_IPS.split(",") if STORAGE_ACCOUNT_ALLOWED_IPS else []
    print(f'Whitelisting {allowed_ips} IP(s) to access `{storage_account_name}` storage account.')
    for ip in allowed_ips:
        ip_rules.append(IPRule(ip_address_or_range=ip))

    storage_account_config = StorageAccountCreateParameters(
        sku=Sku(name=SkuName.STANDARD_LRS),
        kind=Kind.STORAGE_V2,
        access_tier=AccessTier.HOT,
        location=REGION,
        minimum_tls_version=MinimumTlsVersion.TLS1_2,
        encryption=Encryption(
            services=EncryptionServices(
                table=EncryptionService(key_type=KeyType.ACCOUNT),
                queue=EncryptionService(key_type=KeyType.ACCOUNT)),
            require_infrastructure_encryption=True
        ),
        network_rule_set=NetworkRuleSet(
            bypass=Bypass.AZURE_SERVICES,
            default_action=DefaultAction.DENY,
            virtual_network_rules=[VirtualNetworkRule(
                virtual_network_resource_id=VNET_ID
            )],
            ip_rules=ip_rules
        ),
        tags={
            "managed-by": "python",
            "infrastructure": "attorney-onboarding"
        }
    )


    storage_account = storage_account_client.storage_accounts.begin_create(RESOURCE_GROUP_NAME, storage_account_name, storage_account_config) # type: ignore
    print(f'Started - Storage account `{storage_account_name}` creation.')
    storage_account.wait()

    storage_account_properties = storage_account_client.storage_accounts.get_properties(RESOURCE_GROUP_NAME, storage_account_name)

    if (storage_account_properties.provisioning_state == 'Succeeded'):
        print(f'Succeeded - Storage account `{storage_account_name}` creation.')
        blob_client = BlobServiceClient(f'https://{storage_account_name}.blob.core.windows.net/', get_credentials())
        blob_client.set_service_properties(delete_retention_policy=RetentionPolicy(enabled=True, days=7))

        storage_account_client.blob_containers.create(RESOURCE_GROUP_NAME, storage_account_name, CONTAINER_NAME, {}) # type: ignore
        print(f'Succeeded - Blob container `{CONTAINER_NAME}` created in `{storage_account_name}` storage account.')

        # keys = storage_account_client.storage_accounts.list_keys(RESOURCE_GROUP_NAME, storage_account_name)
        # print(keys)

    elif (storage_account_properties.provisioning_state == 'Failed'):
        print(f'Failed - Storage account `{storage_account_name}` creation.')

    return storage_account_properties


def main(name: str) -> dict:
    storage_account = create_storage_account(name)

    return {
        'resource': 'storageAccount',
        'name': storage_account.name
    }