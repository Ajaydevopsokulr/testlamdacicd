import os
import json
import boto3
from jose import jwt
import base64

ddb = boto3.resource('dynamodb')
conn_table = ddb.Table(os.environ['CONNECTIONS_TABLE'])


def get_public_key():
    """
    Decode and return the public key from environment variable.
    Handles base64 decoding with proper error handling.
    """
    public_key_env = os.environ.get("PUBLIC_KEY")
    if not public_key_env:
        raise Exception("PUBLIC_KEY not configured")
    
    try:
        # Remove any whitespace/newlines that might cause padding issues
        public_key_env = public_key_env.strip()
        # Add padding if needed
        missing_padding = len(public_key_env) % 4
        if missing_padding:
            public_key_env += '=' * (4 - missing_padding)
        
        return base64.b64decode(public_key_env)
    except Exception as e:
        raise Exception(f"Failed to decode PUBLIC_KEY: {str(e)}")


def extract_user_id(token: str):
    """
    Validate RS256 JWT and extract user_id field
    """
    if token.startswith("Bearer "):
        token = token.replace("Bearer ", "")

    public_key = get_public_key()

    payload = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        options={"verify_aud": False}
    )

    user_id = payload.get("user_id")
    if not user_id:
        raise Exception("user_id missing in token")

    return user_id


def lambda_handler(event, context):
    # Debug: print the entire event to see structure
    print("Event received:", json.dumps(event))
    
    headers = event.get("headers", {})
    print("Headers:", json.dumps(headers))

    cors_headers = {
        "Access-Control-Allow-Origin": "http://183.83.199.230:5173",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
    }

    # Get token from Authorization header (try different casings)
    token = headers.get("Authorization") or headers.get("authorization") or headers.get("AUTHORIZATION")
    
    if not token:
        return {"statusCode": 401, "headers": cors_headers, "body": json.dumps({"error": "Missing Authorization token", "headers_received": list(headers.keys())})}

    # Extract user_id from JWT token
    try:
        user_id = extract_user_id(token)
    except Exception as e:
        print("JWT validation failed:", str(e))
        return {"statusCode": 403, "headers": cors_headers, "body": "Invalid JWT token"}

    # Find and delete all connections for this user using GSI
    deleted_count = 0
    try:
        # Use Query with GSI - faster and cheaper than Scan
        response = conn_table.query(
            IndexName="user_id-index",
            KeyConditionExpression="user_id = :uid",
            ExpressionAttributeValues={
                ":uid": user_id
            }
        )
        
        # Delete all connections for this user
        for item in response.get("Items", []):
            conn_id = item.get("connectionId")
            try:
                conn_table.delete_item(Key={"connectionId": conn_id})
                deleted_count += 1
                print(f"Deleted connection: {conn_id} for user: {user_id}")
            except Exception as e:
                print(f"Failed to delete connection {conn_id}: {e}")
        
        print(f"Total connections deleted for user {user_id}: {deleted_count}")
        
    except Exception as e:
        print(f"Error finding connections: {e}")
        return {
            "statusCode": 200,
            "headers": cors_headers,
            "body": json.dumps({
                "message": "No connections found",
                "deleted_connections": 0,
                "user_id": user_id
            })
        }

    return {
        "statusCode": 200,
        "headers": cors_headers,
        "body": json.dumps({
            "message": "Disconnected successfully",
            "deleted_connections": deleted_count,
            "user_id": user_id
        })
    }
