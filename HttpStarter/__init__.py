import logging
import azure.functions as func
import azure.durable_functions as df

async def main(request: func.HttpRequest, starter: str) -> func.HttpResponse:
    client = df.DurableOrchestrationClient(starter)
    
    organization_name = request.params['query'].split('.')[0]
    instance_id = await client.start_new(request.route_params["functionName"], None, organization_name)

    logging.info(f"Started orchestration with ID = '{instance_id}'.")
    return client.create_check_status_response(request, instance_id)