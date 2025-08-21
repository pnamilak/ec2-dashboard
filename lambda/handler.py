import boto3
import json

ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    params = event.get("queryStringParameters") or {}
    action = params.get("action")
    env = params.get("env")
    instance_id = params.get("instance_id")

    if action == "list" and env:
        return list_instances(env)
    elif action in ["start", "stop"] and instance_id:
        return start_stop_instance(instance_id, action)
    return respond(400, "Invalid request")

def list_instances(env):
    pattern = f"*{env.lower()}*"
    resp = ec2.describe_instances(Filters=[{"Name": "tag:Name", "Values": [pattern]}])

    items = []
    for r in resp.get("Reservations", []):
        for i in r.get("Instances", []):
            name = next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), "")
            items.append({
                "Name": name,
                "InstanceId": i["InstanceId"],
                "State": i["State"]["Name"]
            })

    return respond(200, items)


def start_stop_instance(instance_id, action):
    if action == "start":
        ec2.start_instances(InstanceIds=[instance_id])
    else:
        ec2.stop_instances(InstanceIds=[instance_id])
    return respond(200, f"{action.title()} request sent for {instance_id}")

def respond(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Content-Type": "application/json"
        },
        "body": json.dumps(body)
    }
