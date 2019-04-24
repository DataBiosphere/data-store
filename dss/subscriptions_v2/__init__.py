import os
import json

from dss.config import Replica
from dss import dynamodb  # type: ignore


class SubscriptionData:
    REPLICA = 'replica'
    OWNER = 'owner'
    UUID = 'uuid'
    CALLBACK_URL = 'callback_url'
    JMESPATH_QUERY = 'jmespath_query'
    METHOD = 'method'
    ENCODING = 'encoding'
    FORM_FIELDS = 'form_fields'
    PAYLOAD_FORM_FIELD = 'payload_form_field'
    ATTACHMENTS = 'attachments'


subscription_db_table = f"dss-subscriptions-v2-{{}}-{os.environ['DSS_DEPLOYMENT_STAGE']}"


def put_subscription(doc: dict):
    dynamodb.put_item(table=subscription_db_table.format(doc[SubscriptionData.REPLICA].name),
                      hash_key=doc[SubscriptionData.OWNER],
                      sort_key=doc[SubscriptionData.UUID],
                      value=json.dumps(doc))


def get_subscription(replica: Replica, owner: str, uuid: str):
    item = dynamodb.get_item(table=subscription_db_table.format(replica.name),
                             hash_key=owner,
                             sort_key=uuid)
    return json.loads(item)


def get_subscriptions_for_owner(replica: Replica, owner: str) -> list:
    items = dynamodb.get_primary_key_items(table=subscription_db_table.format(replica.name),
                                           key=owner)
    return [json.loads(item) for item in items]


def get_subscriptions_for_replica(replica: Replica) -> list:
    items = dynamodb.get_all_table_items(table=subscription_db_table.format(replica.name))
    return [json.loads(item) for item in items]


def delete_subscription(replica: Replica, owner: str, uuid: str):
    dynamodb.delete_item(table=subscription_db_table.format(replica.name),
                         hash_key=owner,
                         sort_key=uuid)
