import base64, os, tempfile, shutil, yaml
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.sql import SqlManagementClient
from azure.cli.core import get_default_cli
from azure.containerregistry import ArtifactTagOrder, ContainerRegistryClient

AKS_CLUSTER_NAME=str(os.getenv('AKS_CLUSTER_NAME'))
AKS_CLUSTER_RESOURCE_GROUP_NAME=str(os.getenv('AKS_CLUSTER_RESOURCE_GROUP_NAME'))
AZURE_CLIENT_ID=str(os.getenv('AZURE_CLIENT_ID'))
AZURE_CLIENT_SECRET=str(os.getenv('AZURE_CLIENT_SECRET'))
AZURE_CLIENT_SECRET_PACS=str(os.getenv('AZURE_CLIENT_SECRET_PACS'))
AZURE_DICOM_PACS_BASE_URL=str(os.getenv('AZURE_DICOM_PACS_BASE_URL'))
AZURE_FHIR_BASE_URL=str(os.getenv('AZURE_FHIR_BASE_URL'))
CLIENT_ID=str(os.getenv('CLIENT_ID'))
CLIENT_SECRET=str(os.getenv('CLIENT_SECRET'))
CONTAINER_REGISTRY_ENDPOINT=str(os.getenv('CONTAINER_REGISTRY_ENDPOINT'))
DICOM_VIEWER_URL=str(os.getenv('DICOM_VIEWER_URL'))
KEY_VAULT_URL=str(os.getenv('KEY_VAULT_URL'))
MATRIX_CHAT_URL=str(os.getenv('MATRIX_CHAT_URL'))
RESOURCE_GROUP_NAME=str(os.getenv('RESOURCE_GROUP_NAME'))
SUBSCRIPTION_ID=str(os.getenv('SUBSCRIPTION_ID'))
TENANT_ID=str(os.getenv('TENANT_ID'))

az_cli = get_default_cli()
az_cli.invoke(['login', '--service-principal', '-u', CLIENT_ID, '-p', CLIENT_SECRET, '--tenant', TENANT_ID])
az_cli.invoke(['account', 'set', '--subscription', SUBSCRIPTION_ID])
az_cli.invoke(['aks', 'get-credentials', '--resource-group', AKS_CLUSTER_RESOURCE_GROUP_NAME, '--name', AKS_CLUSTER_NAME, '--overwrite-existing'])


credentials = ClientSecretCredential(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tenant_id=TENANT_ID)


def create_temp_dir(organization_name: str):
    path = tempfile.gettempdir()
    tmp_dir = os.path.join(path, organization_name)
    shutil.copytree('CreateKubernetesObjects', tmp_dir, dirs_exist_ok=True)
    print(f'Copied files from `CreateKubernetesObjects` directory to `{tmp_dir}` directory.')
    return tmp_dir


def delete_temp_dir(tmp_dir):
    shutil.rmtree(tmp_dir)
    print(f'Removed {tmp_dir} directory.')


def get_container_image(respository: str) -> str:
    latest_image = None
    registry_client = ContainerRegistryClient(CONTAINER_REGISTRY_ENDPOINT, credentials, audience='https://management.azure.com')
    images = (registry_client.list_tag_properties(respository, order_by=ArtifactTagOrder.LAST_UPDATED_ON_DESCENDING))

    for image in images:
        latest_image = image.name
        break
    return str(latest_image)


def create_namespace(resource_name: str, tmp_dir: str):
    ''' Creates Kubernetes Namespace object '''
    
    with open(f'{tmp_dir}/namespace.yml', 'r') as infile:
        namespace = yaml.safe_load(infile)
        
        namespace['metadata']['name'] = 'attorney-' + resource_name
        namespace['metadata']['labels']['name'] = resource_name
    infile.close()
    
    with open(f'{tmp_dir}/namespace.yml', 'w') as outfile:
        yaml.dump(namespace, outfile)
    outfile.close()

    az_cli.invoke(['aks', 'command', 'invoke', '--resource-group', AKS_CLUSTER_RESOURCE_GROUP_NAME, '--name', AKS_CLUSTER_NAME, '--command', 'kubectl apply -f namespace.yml', '--file', f'{tmp_dir}/namespace.yml'])


def create_configmap(resource_name: str, tmp_dir: str):
    ''' Creates Kubernetes ConfigMap object '''
    
    with open(f'{tmp_dir}/configmap.yml', 'r') as infile:
        configmap = yaml.safe_load(infile)
        
        configmap['metadata']['namespace'] = 'attorney-' + resource_name
        configmap['metadata']['labels']['name'] = resource_name
        configmap['data']['API_BASE_URL'] = f'https://{resource_name}-service.caseclinical.com'
        configmap['data']['AZURE_DICOM_PACS_BASE_URL'] = AZURE_DICOM_PACS_BASE_URL
        configmap['data']['AZURE_FHIR_BASE_URL'] = AZURE_FHIR_BASE_URL
        configmap['data']['AZURE_STORAGE_ACCOUNT_NAME'] = resource_name
        configmap['data']['AZURE_TENANT_ID'] = TENANT_ID
        configmap['data']['DICOM_VIEWER_URL'] = DICOM_VIEWER_URL
        configmap['data']['MATRIX_CHAT_URL'] = MATRIX_CHAT_URL
        configmap['data']['WEB_URL'] = f'https://{resource_name}.caseclinical.com'
        configmap['data']['WSS_URL'] = f'https://{resource_name}-service.caseclinical.com/graphql'
    infile.close()
    
    with open(f'{tmp_dir}/configmap.yml', 'w') as outfile:
        yaml.dump(configmap, outfile)
    outfile.close()

    az_cli.invoke(['aks', 'command', 'invoke', '--resource-group', AKS_CLUSTER_RESOURCE_GROUP_NAME, '--name', AKS_CLUSTER_NAME, '--command', 'kubectl apply -f configmap.yml', '--file', f'{tmp_dir}/configmap.yml'])


def key_vault_secret_client():
    client = SecretClient(KEY_VAULT_URL, credentials)
    return client


def encode_conn_string(db_conn_string: str) -> str:
    return base64.b64encode(db_conn_string.encode('utf-8')).decode('utf-8')


def get_conn_string(database_name: str, server_name: str) -> str:
    secret_client = key_vault_secret_client()
    
    db_conn_string = secret_client.get_secret(database_name + '-' + server_name + '-connection-string')
    return str(db_conn_string.value)


def get_database_server(database_name: str):
    sql_client = SqlManagementClient(credentials, SUBSCRIPTION_ID)
    servers = sql_client.servers.list_by_resource_group(RESOURCE_GROUP_NAME)
    for server in servers:
        databases = sql_client.databases.list_by_server(RESOURCE_GROUP_NAME, str(server.name))
        for database in databases:
            if (database.name == database_name):
                return server.name


def create_secret(resource_name: str, tmp_dir: str):
    ''' Creates Kubernetes Secret object '''
    
    with open(f'{tmp_dir}/secrets.yml', 'r') as infile:
        secret = yaml.safe_load(infile)
        
        secret['metadata']['namespace'] = 'attorney-' + resource_name
        secret['metadata']['labels']['name'] = resource_name
        secret['data']['AZURE_CLIENT_ID'] = AZURE_CLIENT_ID
        secret['data']['AZURE_CLIENT_SECRET'] = AZURE_CLIENT_SECRET
        secret['data']['AZURE_CLIENT_SECRET_PACS'] = AZURE_CLIENT_SECRET_PACS
        # secret['data']['AZURE_STORAGE_ACCOUNT_CONNECTION_STRING'] = ''
        # secret['data']['AZURE_STORAGE_ACCOUNT_KEY'] = ''
        # secret['data']['AZURE_STORAGE_ACCOUNT_SAS_KEY'] = ''
        # secret['data']['AZURE_STORAGE_ACCOUNT_URL'] = ''
        secret['data']['DATABASE_URL'] = f'{encode_conn_string(get_conn_string(resource_name, str(get_database_server(resource_name))))}'
    infile.close()
    
    with open(f'{tmp_dir}/secrets.yml', 'w') as outfile:
        yaml.dump(secret, outfile)
    outfile.close()

    # TLS Cert
    with open(f'{tmp_dir}/ingress-tls-cert.yml', 'r') as tls_cert_infile:
        tls_cert = yaml.safe_load(tls_cert_infile)
        tls_cert['metadata']['namespace'] = 'attorney-' + resource_name
        tls_cert['metadata']['labels']['name'] = resource_name
    tls_cert_infile.close()
    
    with open(f'{tmp_dir}/ingress-tls-cert.yml', 'w') as tls_cert_outfile:
        yaml.dump(tls_cert, tls_cert_outfile)
    tls_cert_outfile.close()

    az_cli.invoke(['aks', 'command', 'invoke', '--resource-group', AKS_CLUSTER_RESOURCE_GROUP_NAME, '--name', AKS_CLUSTER_NAME, '--command', 'kubectl apply -f secrets.yml', '--file', f'{tmp_dir}/secrets.yml'])
    az_cli.invoke(['aks', 'command', 'invoke', '--resource-group', AKS_CLUSTER_RESOURCE_GROUP_NAME, '--name', AKS_CLUSTER_NAME, '--command', 'kubectl apply -f ingress-tls-cert.yml', '--file', f'{tmp_dir}/ingress-tls-cert.yml'])


def create_deployment(resource_name: str, tmp_dir: str):
    ''' Creates Kubernetes Deployment object '''
    
    # Create FE Deployment
    with open(f'{tmp_dir}/caseclinical-fuse-frontend-deployment.yml', 'r') as infile:
        frontend_deployment = yaml.safe_load(infile)
        frontend_deployment['metadata']['namespace'] = 'attorney-' + resource_name
        frontend_deployment['metadata']['labels']['name'] = resource_name
        frontend_deployment['spec']['template']['metadata']['labels']['name'] = resource_name
        frontend_deployment['spec']['template']['spec']['containers'][0]['image'] = CONTAINER_REGISTRY_ENDPOINT.split('//')[-1] + '/' + 'caseclinical-fuse-frontend:' + '{}'.format(get_container_image('caseclinical-fuse-frontend'))
    infile.close()
    
    with open(f'{tmp_dir}/caseclinical-fuse-frontend-deployment.yml', 'w') as outfile:
        yaml.dump(frontend_deployment, outfile)
    outfile.close()

    # Create BE Deployment
    with open(f'{tmp_dir}/caseclinical-fuse-service-deployment.yml', 'r') as infile:
        service_deployment = yaml.safe_load(infile)
        service_deployment['metadata']['namespace'] = 'attorney-' + resource_name
        service_deployment['metadata']['labels']['name'] = resource_name
        service_deployment['spec']['template']['metadata']['labels']['name'] = resource_name
        service_deployment['spec']['template']['spec']['initContainers'][0]['image'] = CONTAINER_REGISTRY_ENDPOINT.split('//')[-1] + '/' + 'caseclinical-fuse-migration:' + '{}'.format(get_container_image('caseclinical-fuse-migration'))
        service_deployment['spec']['template']['spec']['containers'][0]['image'] = CONTAINER_REGISTRY_ENDPOINT.split('//')[-1] + '/' + 'caseclinical-fuse-service:' + '{}'.format(get_container_image('caseclinical-fuse-service'))
    infile.close()
    
    with open(f'{tmp_dir}/caseclinical-fuse-service-deployment.yml', 'w') as outfile:
        yaml.dump(service_deployment, outfile)

    az_cli.invoke(['aks', 'command', 'invoke', '--resource-group', AKS_CLUSTER_RESOURCE_GROUP_NAME, '--name', AKS_CLUSTER_NAME, '--command', 'kubectl apply -f caseclinical-fuse-frontend-deployment.yml', '--file', f'{tmp_dir}/caseclinical-fuse-frontend-deployment.yml'])
    az_cli.invoke(['aks', 'command', 'invoke', '--resource-group', AKS_CLUSTER_RESOURCE_GROUP_NAME, '--name', AKS_CLUSTER_NAME, '--command', 'kubectl apply -f caseclinical-fuse-service-deployment.yml', '--file', f'{tmp_dir}/caseclinical-fuse-service-deployment.yml'])


def create_svc(resource_name: str, tmp_dir: str):
    ''' Creates Kubernetes Service object '''
    
    # Create FE Service
    with open(f'{tmp_dir}/frontend-svc.yml', 'r') as frontend_infile:
        service = yaml.safe_load(frontend_infile)
        service['metadata']['namespace'] = 'attorney-' + resource_name
        service['metadata']['labels']['name'] = resource_name
        service['spec']['selector']['name'] = resource_name
    frontend_infile.close()
    
    with open(f'{tmp_dir}/frontend-svc.yml', 'w') as frontend_outfile:
        yaml.dump(service, frontend_outfile)
    frontend_outfile.close()

    # Create BE Service
    with open(f'{tmp_dir}/backend-svc.yml', 'r') as backend_infile:
        service = yaml.safe_load(backend_infile)
        service['metadata']['namespace'] = 'attorney-' + resource_name
        service['metadata']['labels']['name'] = resource_name
        service['spec']['selector']['name'] = resource_name
    backend_infile.close()
    
    with open(f'{tmp_dir}/backend-svc.yml', 'w') as backend_outfile:
        yaml.dump(service, backend_outfile)
    backend_outfile.close()

    az_cli.invoke(['aks', 'command', 'invoke', '--resource-group', AKS_CLUSTER_RESOURCE_GROUP_NAME, '--name', AKS_CLUSTER_NAME, '--command', 'kubectl apply -f frontend-svc.yml', '--file', f'{tmp_dir}/frontend-svc.yml'])
    az_cli.invoke(['aks', 'command', 'invoke', '--resource-group', AKS_CLUSTER_RESOURCE_GROUP_NAME, '--name', AKS_CLUSTER_NAME, '--command', 'kubectl apply -f backend-svc.yml', '--file', f'{tmp_dir}/backend-svc.yml'])


def create_hpa(resource_name: str, tmp_dir: str):
    ''' Creates Kubernetes HorizontalPodAutoscaling object '''
    
    # Create FE HPA
    with open(f'{tmp_dir}/frontend-hpa.yml', 'r') as frontend_infile:
        hpa = yaml.safe_load(frontend_infile)
        hpa['metadata']['namespace'] = 'attorney-' + resource_name
        hpa['metadata']['labels']['name'] = resource_name
    frontend_infile.close()
    
    with open(f'{tmp_dir}/frontend-hpa.yml', 'w') as frontend_outfile:
        yaml.dump(hpa, frontend_outfile)
    frontend_outfile.close()

    # Create BE HPA
    with open(f'{tmp_dir}/backend-hpa.yml', 'r') as backend_infile:
        hpa = yaml.safe_load(backend_infile)
        hpa['metadata']['namespace'] = 'attorney-' + resource_name
        hpa['metadata']['labels']['name'] = resource_name
    backend_infile.close()
    with open(f'{tmp_dir}/backend-hpa.yml', 'w') as backend_outfile:
        yaml.dump(hpa, backend_outfile)
    backend_outfile.close()

    az_cli.invoke(['aks', 'command', 'invoke', '--resource-group', AKS_CLUSTER_RESOURCE_GROUP_NAME, '--name', AKS_CLUSTER_NAME, '--command', 'kubectl apply -f frontend-hpa.yml', '--file', f'{tmp_dir}/frontend-hpa.yml'])
    az_cli.invoke(['aks', 'command', 'invoke', '--resource-group', AKS_CLUSTER_RESOURCE_GROUP_NAME, '--name', AKS_CLUSTER_NAME, '--command', 'kubectl apply -f backend-hpa.yml', '--file', f'{tmp_dir}/backend-hpa.yml'])


def create_ingress(resource_name: str, tmp_dir: str):
    ''' Creates Kubernetes Ingress object '''
    
    with open(f'{tmp_dir}/appgw-ingress.yml', 'r') as infile:
        ingress = yaml.safe_load(infile)
        ingress['metadata']['namespace'] = 'attorney-' + resource_name
        ingress['metadata']['labels']['name'] = resource_name
        ingress['spec']['tls'][0]['hosts'][0] = resource_name + '.caseclinical.com'
        ingress['spec']['tls'][0]['hosts'][1] = resource_name + '-service.caseclinical.com'
        ingress['spec']['rules'][0]['host'] = resource_name + '.caseclinical.com'
        ingress['spec']['rules'][1]['host'] = resource_name + '-service.caseclinical.com'
    infile.close()
    with open(f'{tmp_dir}/appgw-ingress.yml', 'w') as outfile:
        yaml.dump(ingress, outfile)
    outfile.close()

    az_cli.invoke(['aks', 'command', 'invoke', '--resource-group', AKS_CLUSTER_RESOURCE_GROUP_NAME, '--name', AKS_CLUSTER_NAME, '--command', 'kubectl apply -f appgw-ingress.yml', '--file', f'{tmp_dir}/appgw-ingress.yml'])


def main(name: str):
    tmp_dir = create_temp_dir(name)

    try: 
        create_namespace(name, tmp_dir)
        create_configmap(name, tmp_dir)
        create_secret(name, tmp_dir)
        create_deployment(name, tmp_dir)
        create_svc(name, tmp_dir)
        create_hpa(name, tmp_dir)
        create_ingress(name, tmp_dir)

    except Exception as err:
        print(err)

    finally:
        delete_temp_dir(tmp_dir)

    return {
        'resource': 'kubernetes',
        'name': name
    }