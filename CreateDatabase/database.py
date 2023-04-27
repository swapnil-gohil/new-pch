import os, random, string, pyodbc, uuid
from azure.identity import ClientSecretCredential
from azure.keyvault.keys import KeyClient, KeyOperation
from azure.keyvault.secrets import KeyVaultSecret, SecretClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.authorization.models import PrincipalType, RoleAssignmentCreateParameters
from azure.mgmt.keyvault.models import AccessPolicyEntry, AccessPolicyUpdateKind, KeyPermissions, Permissions,  VaultAccessPolicyParameters, VaultAccessPolicyProperties
from azure.mgmt.monitor.models import DiagnosticSettingsResource, LogSettings, MetricSettings
from azure.mgmt.sql.models import AdministratorName, AdministratorType, BackupStorageRedundancy, BlobAuditingPolicyState, CatalogCollationType, CreateMode, Database, ExtendedServerBlobAuditingPolicy, FirewallRule, IdentityType, LongTermRetentionPolicy, LongTermRetentionPolicyName, ManagementOperationState, ResourceIdentity, SecurityAlertPolicyName, SecurityAlertPolicyState, Server, ServerAzureADAdministrator, ServerKey, ServerKeyType, ServerSecurityAlertPolicy, ServerVulnerabilityAssessment, Sku, VirtualNetworkRule, VulnerabilityAssessmentName, VulnerabilityAssessmentRecurringScansProperties 


AAD_ADMIN_LOGIN=str(os.getenv('AAD_ADMIN_LOGIN'))
AAD_ADMIN_SID=str(os.getenv('AAD_ADMIN_SID'))
ADMINISTRATOR_LOGIN_USERNAME=str(os.getenv('ADMINISTRATOR_LOGIN_USERNAME'))
CLIENT_ID=str(os.getenv('CLIENT_ID'))
CLIENT_SECRET=str(os.getenv('CLIENT_SECRET'))
COMPLIANCE_STORAGE_ACCOUNT_ID=str(os.getenv('COMPLIANCE_STORAGE_ACCOUNT_ID'))
COMPLIANCE_STORAGE_ACCOUNT_RESOURCE_GROUP_NAME=COMPLIANCE_STORAGE_ACCOUNT_ID.split('/')[4]
DATABASE_LOGIN_USERNAME=str(os.getenv('DATABASE_LOGIN_USERNAME'))
KEY_VAULT_URL=str(os.getenv('KEY_VAULT_URL'))
KEY_VAULT_RESOURCE_GROUP_NAME=str(os.getenv('KEY_VAULT_RESOURCE_GROUP_NAME'))
REGION=str(os.getenv('REGION'))
RESOURCE_GROUP_NAME=str(os.getenv('RESOURCE_GROUP_NAME'))
SQL_SERVER_ALLOWED_IPS=str(os.getenv('SQL_SERVER_ALLOWED_IPS')) #"x.x.x.x,y.y.y.y"
STORAGE_ACCOUNT_NAME=COMPLIANCE_STORAGE_ACCOUNT_ID.split('/')[-1]
SUBSCRIPTION_ID=str(os.getenv('SUBSCRIPTION_ID'))
TENANT_ID=str(os.getenv('TENANT_ID'))
VNET_ID=str(os.getenv('VNET_ID'))

credentials = ClientSecretCredential(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tenant_id=TENANT_ID)

sql_client = SqlManagementClient(credentials, SUBSCRIPTION_ID)


def enable_diagnostic_settings(server_name: str , database_name: str):
    monitor_client = MonitorManagementClient(credentials, SUBSCRIPTION_ID)

    diagnostic_settings_config = DiagnosticSettingsResource(
        storage_account_id=COMPLIANCE_STORAGE_ACCOUNT_ID,
        logs=[LogSettings(enabled=True, category='SQLInsights'), LogSettings(enabled=True, category='AutomaticTuning'), 
              LogSettings(enabled=True, category='QueryStoreRuntimeStatistics'), LogSettings(enabled=True, category='QueryStoreWaitStatistics'),
              LogSettings(enabled=True, category='Errors'), LogSettings(enabled=True, category='DatabaseWaitStatistics'),
              LogSettings(enabled=True, category='Timeouts'), LogSettings(enabled=True, category='Blocks'),
              LogSettings(enabled=True, category='Deadlocks'), LogSettings(enabled=True, category='DevOpsOperationsAudit'),
              LogSettings(enabled=True, category='SQLSecurityAuditEvents')],
        metrics=[MetricSettings(enabled=True, category='Basic'), MetricSettings(enabled=True, category='InstanceAndAppAdvanced'), 
                 MetricSettings(enabled=True, category='WorkloadManagement')]
        )

    monitor_client.diagnostic_settings.create_or_update(f'/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP_NAME}/providers/Microsoft.Sql/servers/{server_name}/databases/{database_name}', 'setByPython', diagnostic_settings_config) # type: ignore
    print(f'Enabled - Diagnostic settings for `{database_name}` database.')


def get_sql_servers() -> list:
    resource_group_client = ResourceManagementClient(credentials, SUBSCRIPTION_ID)
    servers = []
    sql_servers = resource_group_client.resources.list_by_resource_group(RESOURCE_GROUP_NAME, filter=f"resourceType eq 'Microsoft.Sql/servers'") # type: ignore

    for server in sql_servers:
        servers.append(server.as_dict()['name'])

    print(f'Available MSSQL servers - {servers}')
    return servers


def enable_long_term_retention_backup(server_name: str, database_name: str):
    ltr = LongTermRetentionPolicy(
        weekly_retention="P2W",
        week_of_year=1
    )
    
    sql_client.long_term_retention_policies.begin_create_or_update(RESOURCE_GROUP_NAME, server_name, database_name, LongTermRetentionPolicyName.DEFAULT, ltr)
    print(f'Enabled - Long Term Retention backup of `{database_name}` database.')


def create_sql_cmk(server_name: str):
    key_client = KeyClient(KEY_VAULT_URL, credentials)

    create_rsa_key = key_client.create_rsa_key(server_name + '-key', size=2048, enabled=True, key_operations=[KeyOperation.decrypt, KeyOperation.encrypt, KeyOperation.sign, KeyOperation.wrap_key, KeyOperation.unwrap_key,
                                               KeyOperation.verify], tags={'resource': 'sql-server-cmk', 'server-name': server_name, 'type': 'rsa-key', 'managed-by': 'python', 'infrastructure': 'attorney-onboarding'})

    print(f'Created - Customer Managed Key `{create_rsa_key.name}` in `{KEY_VAULT_URL.split("//")[-1].split(".")[0]}` key vault.')
    return create_rsa_key.name


def enable_transparent_data_encryption(server_name: str):
    tde = ServerKey(
        auto_rotation_enabled=True,
        server_key_type=ServerKeyType.AZURE_KEY_VAULT,
        uri=KEY_VAULT_URL
    )

    sql_client.server_keys.begin_create_or_update(RESOURCE_GROUP_NAME, server_name, create_sql_cmk(server_name), tde)
    print(f'Enabled - Transparent Data Encryption using CMK on `{server_name}` SQL server.')
    

def storage_account_client():
    client = StorageManagementClient(credentials, SUBSCRIPTION_ID)
    return client


def create_blob_container(server_name: str):
    storage_client = storage_account_client()

    storage_client.blob_containers.create(COMPLIANCE_STORAGE_ACCOUNT_ID.split('/')[4], STORAGE_ACCOUNT_NAME, server_name + '-vulnerability-logs', {}) # type: ignore
    print(f'Created - Blob container `{server_name}-vulnerability-logs` in `{STORAGE_ACCOUNT_NAME}` storage account.')
    return f'https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net/{server_name}-vulnerability-logs/'


def security_alerty_policy(server_name: str):
    security_alert_policy = ServerSecurityAlertPolicy(
        state=SecurityAlertPolicyState.ENABLED,
        retention_days=30
    )
    
    sql_client.server_security_alert_policies.begin_create_or_update(RESOURCE_GROUP_NAME, server_name, SecurityAlertPolicyName.DEFAULT, security_alert_policy)
    return True


def enable_server_vulnerability_assessment(server_name: str):
    if (security_alerty_policy(server_name)):
        va = ServerVulnerabilityAssessment(
            storage_container_path=create_blob_container(server_name),
            recurring_scans=VulnerabilityAssessmentRecurringScansProperties(
                is_enabled=True,
                email_subscription_admins=True
            ))

        sql_client.server_vulnerability_assessments.create_or_update(RESOURCE_GROUP_NAME, server_name, VulnerabilityAssessmentName.DEFAULT, va)
        print(f'Enabled - Vulnerability Assessment logs for `{server_name}` SQL server.')


def create_sql_server_role_assignment(server_name: str, sql_server_properties):
    auth_client = AuthorizationManagementClient(credentials, SUBSCRIPTION_ID)
    
    role_assignment = RoleAssignmentCreateParameters(
        role_definition_id="/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe",
        principal_id=sql_server_properties.identity.principal_id,
        principal_type=PrincipalType.SERVICE_PRINCIPAL
    )
    
    auth_client.role_assignments.create(COMPLIANCE_STORAGE_ACCOUNT_ID, str(uuid.uuid1()), role_assignment) # type: ignore
    print(f'Created - Role Assignment for `{server_name}` SQL server to access `{STORAGE_ACCOUNT_NAME}` storage account.')
    return True


def enable_server_auditing_policy(server_name: str, sql_server_properties):
    if (create_sql_server_role_assignment(server_name, sql_server_properties)):
        server_auditing_policy = ExtendedServerBlobAuditingPolicy(
            is_managed_identity_in_use=True,
            retention_days=7,
            state=BlobAuditingPolicyState.ENABLED,
            storage_endpoint=f'https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net/'
        )
        
        sql_client.extended_server_blob_auditing_policies.begin_create_or_update(RESOURCE_GROUP_NAME, server_name, server_auditing_policy)
        print(f'Enabled - Server Auditing policy for `{server_name}` SQL server.')


def enable_service_endpoint(server_name: str):
    vnet_rule = VirtualNetworkRule(
        virtual_network_subnet_id=VNET_ID
    )
    sql_client.virtual_network_rules.begin_create_or_update(RESOURCE_GROUP_NAME, server_name, 'pch-vnet', vnet_rule)
    print(f'Enabled - Service endpoint in `{server_name}` SQL server.')


def enable_firewall_rules(server_name: str):
    allowed_ips = SQL_SERVER_ALLOWED_IPS.split(',') if SQL_SERVER_ALLOWED_IPS else []
    for ip in allowed_ips:
        firewall_name = f'AllowInboundAccessFrom_{ip.replace(".", "_")}'
        firewall_rule = FirewallRule(
            start_ip_address=ip,
            end_ip_address=ip
        )
        sql_client.firewall_rules.create_or_update(RESOURCE_GROUP_NAME, server_name, firewall_name, firewall_rule)
    print(f'Enabled - Firewall rule in `{server_name}` SQL server.')
    
    
def enable_azure_ad_administrator(server_name: str):
    ad_admin = ServerAzureADAdministrator(
        administrator_type=AdministratorType.ACTIVE_DIRECTORY,
        azure_ad_only_authentication=False,
        login=AAD_ADMIN_LOGIN, # type: ignore
        sid=AAD_ADMIN_SID,
        tenant_id=TENANT_ID
    )

    sql_client.server_azure_ad_administrators.begin_create_or_update(RESOURCE_GROUP_NAME, server_name, AdministratorName.ACTIVE_DIRECTORY, ad_admin)
    print(f'Enabled - Azure AD Administrator for `{server_name}` SQL server.')


def key_vault_secret_client():
    client = SecretClient(KEY_VAULT_URL, credentials)
    return client


def create_sql_server_secret(server_name: str, administrator_login_password):
    secret_client = key_vault_secret_client()
    
    secret_client.set_secret(name=server_name + '-admin-username', value=ADMINISTRATOR_LOGIN_USERNAME, enabled=True, tags={'resource': 'mssql-server', 'server-name': server_name, 'type': 'admin-username', 'managed-by': 'python', 'infrastructure': 'attorney-onboarding'})
    print(f'Created - Secret for Admin username of `{server_name}` SQL server.')
    
    secret_client.set_secret(name=server_name + '-admin-password', value=administrator_login_password, enabled=True, tags={'resource': 'mssql-server', 'server-name': server_name, 'type': 'admin-password', 'managed-by': 'python', 'infrastructure': 'attorney-onboarding'})
    print(f'Created - Secret for Admin password of `{server_name}` SQL server.')


def key_vault_client():
    client = KeyVaultManagementClient(credentials, SUBSCRIPTION_ID)
    return client


def create_key_vault_policy(server_name: str, sql_server_properties):
    client = key_vault_client()
    key_vault_config = AccessPolicyEntry(
        tenant_id=TENANT_ID,
        object_id=sql_server_properties.identity.principal_id,
        permissions=Permissions(keys=[KeyPermissions.GET, KeyPermissions.WRAP_KEY, KeyPermissions.UNWRAP_KEY])
    )
    
    client.vaults.update_access_policy(KEY_VAULT_RESOURCE_GROUP_NAME, KEY_VAULT_URL.split('//')[-1].split('.')[0], AccessPolicyUpdateKind.ADD,
                                       VaultAccessPolicyParameters(properties=VaultAccessPolicyProperties(access_policies=[key_vault_config]))) # type: ignore
    print(f'Created - Key vault access policy for `{server_name}` SQL server.')


def create_sql_server(server_name: str):
    administrator_login_password = generate_password()
    
    server_config = Server(
        location=REGION,
        administrator_login=ADMINISTRATOR_LOGIN_USERNAME,
        administrator_login_password=administrator_login_password,
        version='12.0',
        minimal_tls_version='1.2',
        identity=ResourceIdentity(type=IdentityType.SYSTEM_ASSIGNED),
        tags={
            "managed-by": "python",
            "infrastructure": "attorney-onboarding"
        }
    )

    create_sql_server = sql_client.servers.begin_create_or_update(RESOURCE_GROUP_NAME, server_name, server_config)
    print(f'Started - SQL server `{server_name}` creation.')
    create_sql_server.wait()

    if (ManagementOperationState.SUCCEEDED):
        print(f'Succeeded - SQL Server `{server_name}` creation.')

        sql_server_properties = sql_client.servers.get(RESOURCE_GROUP_NAME, server_name)

        create_key_vault_policy(server_name, sql_server_properties)
        create_sql_server_secret(server_name, administrator_login_password)
        enable_azure_ad_administrator(server_name)
        ## COMPLIANCE REQUIREMENT ##
        enable_firewall_rules(server_name)
        enable_service_endpoint(server_name)
        enable_server_auditing_policy(server_name, sql_server_properties)
        enable_server_vulnerability_assessment(server_name)
        enable_transparent_data_encryption(server_name)

    elif (ManagementOperationState.FAILED):
        print(f'Failed - SQL Server `{server_name}` creation.')


def close_db_conn(cursor, conn):
    cursor.close()
    conn.close()


def create_db_user(cursor, conn, database_name: str):
    try:
        cursor.execute('''
        CREATE USER [{0}] FOR LOGIN [{0}]
        EXEC sp_addrolemember N'db_datareader', N'{0}'
        EXEC sp_addrolemember N'db_datawriter', N'{0}'
        EXEC sp_addrolemember N'db_ddladmin', N'{0}'
        '''.format(DATABASE_LOGIN_USERNAME + database_name))
        conn.commit()
        print(f'Created - Service user in `{database_name}` database.')
    
    except Exception as err:
        conn.rollback()
        print(f'Error occurred when executing the script: {str(err)}')
        
    finally:
        close_db_conn(cursor, conn)


def create_login_user(cursor, conn, database_name: str, database_password: str):
    try:
        cursor.execute('''
        CREATE LOGIN [{0}]
            WITH PASSWORD = '{1}';
        '''.format(DATABASE_LOGIN_USERNAME + database_name, database_password))
        conn.commit()
        print('Created - Service user in `master` database.')
        return True
    
    except Exception as err:
        conn.rollback()
        print(f'Error occurred when executing the script: {str(err)}')

    finally:
        close_db_conn(cursor, conn)


def generate_password():
    password = ''.join(random.choice(char) for char in random.choices(string.ascii_letters + string.digits + '!#', k=16))

    print('Checking password complexity...')
    while not (any(char.islower() for char in password) and any(char.isupper() for char in password) and any(char.isdigit() for char in password) and any(char in '!#' for char in password)):
        print(f'Password did not meet the complexity requirements. Generating a new password again...')
        password = ''.join(random.choice(char) for char in random.choices(string.ascii_letters + string.digits + '!#', k=16))
        
    print('Password matches the complexity requirements.')
    return password


def get_db_conn(server_name: str, database_name: str, administrator_login_password: KeyVaultSecret):
    conn = pyodbc.connect('Driver={};Server=tcp:{}.database.windows.net,1433;Database={};Uid={};Pwd={};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;'
                          .format('{ODBC Driver 17 for SQL Server}', server_name, database_name, ADMINISTRATOR_LOGIN_USERNAME, administrator_login_password.value))
    cursor = conn.cursor()
    return conn, cursor


def execute_sql_script(server_name: str, database_name: str):
    secret_client = key_vault_secret_client()
    administrator_login_password = secret_client.get_secret(server_name + '-admin-password')

    conn, cursor = get_db_conn(server_name, 'master', administrator_login_password)
    database_password = generate_password()
    
    if (create_login_user(cursor, conn, database_name, database_password)):
        conn, cursor = get_db_conn(server_name, database_name, administrator_login_password)
        create_db_user(cursor, conn, database_name)
        
        secret_client.set_secret(name=database_name + '-' + server_name + '-connection-string',
                                value=f'sqlserver://{server_name}.database.windows.net:1433;database={database_name};user={DATABASE_LOGIN_USERNAME + database_name}@{server_name};password={database_password};encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;', 
                                enabled=True, tags={'resource': 'mssql-database', 'server-name': server_name, 'database-name': database_name, 'type': 'connection-string', 'managed-by': 'python', 'infrastructure': 'attorney-onboarding'})
        print(f'Created - Secret for `{database_name}` database connection string.')


def create_sql_database(server_name: str, database_name: str):

    database_config = Database(
        location=REGION,
        sku=Sku(name="GP_S_Gen5_2"), 
        create_mode=CreateMode.DEFAULT,
        collation=CatalogCollationType.SQL_LATIN1_GENERAL_CP1_CI_AS,
        auto_pause_delay=-1,
        requested_backup_storage_redundancy=BackupStorageRedundancy.GEO,
        tags={
            "managed-by": "python",
            "infrastructure": "attorney-onboarding"
        }
    )

    create_sql_database = sql_client.databases.begin_create_or_update(RESOURCE_GROUP_NAME, server_name, database_name, database_config) # type: ignore
    print(f'Started - Database `{database_name}` creation in `{server_name}` SQL server.')
    create_sql_database.wait()

    if (ManagementOperationState.SUCCEEDED):
        print(f'Succeeded - Database `{database_name}` creation in `{server_name}` SQL server.')
        execute_sql_script(server_name, database_name)
        ## COMPLIANCE REQUIREMENT ##
        enable_diagnostic_settings(server_name, database_name)
        enable_long_term_retention_backup(server_name, database_name)

    elif (ManagementOperationState.FAILED):
        print(f'Failed - Database `{database_name}` creation.')


def sql(database_name: str):
    servers = get_sql_servers()

    if (servers == []):
        print(f"Couldn't found any SQL servers in `{RESOURCE_GROUP_NAME}` resource group.")
        server_name = 'pch-mssql-server-uat-attorney-' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
        create_sql_server(server_name)
        create_sql_database(server_name, database_name)
        enable_diagnostic_settings(server_name, database_name='master')

    else:
        count = 0
        for server in servers:
            if (len(list(sql_client.databases.list_by_server(RESOURCE_GROUP_NAME, server))) <= 2000):
                print(f'SQL Server `{server}` consists {len(list(sql_client.databases.list_by_server(RESOURCE_GROUP_NAME, server)))} database(s).')
                create_sql_database(server, database_name)
                count += 1
                break

        if (count == 0):
            print(f'Existing SQL servers in `{RESOURCE_GROUP_NAME}` resource group does not have the capacity to provision new database.')
            server_name = 'pch-mssql-server-attorney-' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
            create_sql_server(server_name)
            create_sql_database(server_name, database_name)
            enable_diagnostic_settings(server_name, database_name='master')


def main(name: str):
    sql(name)

    return {
        'resource': 'database',
        'name': name,
    }