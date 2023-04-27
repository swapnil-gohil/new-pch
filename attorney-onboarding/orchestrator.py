import azure.durable_functions as df

activity_functions = ['CreateStorageAccount', 'CreateDatabase']


def activity_func_status(organization_name: str, storage_account_status: str, database_status: str, application_status: str) -> dict:
    activity_function_status = {
        'storageAccount': {
            'name': organization_name,
            'status': storage_account_status
        },
        'database': {
            'name': organization_name,
            'status': database_status
        },
        'application': {
            'name': organization_name,
            'status': application_status
        }
    }

    return activity_function_status


def orchestrator_function(context: df.DurableOrchestrationContext):
    organization_name = str(context.get_input())

    trigger_storage_account_activity = [context.call_activity(activity_functions[0], organization_name)]
    context.set_custom_status(activity_func_status(organization_name, 'Running', 'Pending', 'Pending'))

    try:
        yield context.task_all(trigger_storage_account_activity)
        context.set_custom_status(activity_func_status(organization_name, 'Succeeded', 'Pending', 'Pending'))
        
        trigger_database_activity = [context.call_activity(activity_functions[1], organization_name)]
        context.set_custom_status(activity_func_status(organization_name, 'Succeeded', 'Running', 'Pending'))
        try:
            yield context.task_all(trigger_database_activity)
            context.set_custom_status(activity_func_status(organization_name, 'Succeeded', 'Succeeded', 'Pending'))
            
            # trigger_kubernetes_activity = [context.call_activity(activity_functions[2], organization_name)]
            # context.set_custom_status(activity_func_status(organization_name, 'Succeeded', 'Succeeded', 'Running'))
    
            # try:
            #     yield context.task_all(trigger_kubernetes_activity)
            #     context.set_custom_status(activity_func_status(organization_name, 'Succeeded', 'Succeeded', 'Succeeded'))
    
            # except Exception as err:
            #     print(f'Failed to setup application on Kubernetes: {err}')
            #     context.set_custom_status(activity_func_status(organization_name, 'Succeeded', 'Succeeded', 'Failed'))
    
        except Exception as err:
            print(f'Failed to create Database: {err}')
            context.set_custom_status(activity_func_status(organization_name, 'Succeeded', 'Failed', 'Postponed'))

    except Exception as err:
        print(f'Failed to create Storage Account: {err}')
        context.set_custom_status(activity_func_status(organization_name, 'Failed', 'Postponed', 'Postponed'))

    
main = df.Orchestrator.create(orchestrator_function)