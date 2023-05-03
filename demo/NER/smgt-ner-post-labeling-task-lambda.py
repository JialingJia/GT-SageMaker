# MIT No Attribution
#
# Copyright 2021 Amazon.com, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import json
import sys

"""
Based off of: https://github.com/aws-samples/aws-sagemaker-ground-truth-recipe/blob/master/aws_sagemaker_ground_truth_sample_lambda/annotation_consolidation_lambda.py


"""
from botocore.exceptions import ClientError
import boto3

# Set to true to enable logging to cloudwatch
# May contain customer annotations
ENABLE_LOGGING = False


def debug(*messages):
    if ENABLE_LOGGING:
        print(*messages)


class S3Client(object):
    """
    Helper Class for S3 operations
    """

    s3_client = boto3.client("s3")
    s3 = boto3.resource("s3")

    def __init__(self, role_arn=None, kms_key_id=None):
        """
        Initialize the S3 resource using provided Role and Kms Key
        :param role_arn: Role which have access to consolidation request S3 payload file.
        :param kms_key_id: KMS key if S3 bucket is encrypted
        :return:
        """
        DEFAULT_SESSION = "Custom_Annotation_Consolidation_Lambda_Session"
        sts_connection = boto3.client("sts")
        assume_role_object = sts_connection.assume_role(
            RoleArn=role_arn, RoleSessionName=DEFAULT_SESSION
        )
        session = boto3.Session(
            aws_access_key_id=assume_role_object["Credentials"]["AccessKeyId"],
            aws_secret_access_key=assume_role_object["Credentials"]["SecretAccessKey"],
            aws_session_token=assume_role_object["Credentials"]["SessionToken"],
        )
        self.s3 = session.resource("s3")
        self.s3_client = session.client("s3")
        self.kms_key_id = kms_key_id

    def put_object_to_s3(self, data, bucket, key, content_type):
        """
        Helper function to persist data in S3
        """
        try:
            if not content_type:
                # Default content type
                content_type = "application/octet-stream"
            image_object = self.s3.Object(bucket, key)
            if self.kms_key_id:
                image_object.put(
                    Body=data,
                    ContentType=content_type,
                    SSEKMSKeyId=self.kms_key_id,
                    ServerSideEncryption="aws:kms",
                )
            else:
                image_object.put(Body=data, ContentType=content_type)
        except ClientError as e:
            raise ValueError(
                "Failed to put data in bucket: {}  with key {}.".format(bucket, key), e
            )
        return "s3://" + image_object.bucket_name + "/" + image_object.key

    def get_object_from_s3(self, s3_url):
        """ Helper function to retrieve data from S3 """
        bucket, path = S3Client.bucket_key_from_s3_uri(s3_url)

        try:
            payload = (
                self.s3_client.get_object(Bucket=bucket, Key=path)
                .get("Body")
                .read()
                .decode("utf-8")
            )
        except ClientError as e:
            debug(e)
            if (
                e.response["Error"]["Code"] == "404"
                or e.response["Error"]["Code"] == "NoSuchKey"
            ):
                return None
            else:
                raise ValueError("Failed to retrieve data from {}.".format(s3_url), e)

        return payload

    @staticmethod
    def bucket_key_from_s3_uri(s3_path):
        """Return bucket and key from s3 URL
        Parameters
        ----------
        s3_path: str, required
            s3 URL of data object ( image/video/text/audio etc )
        Returns
        ------
        bucket: str
            S3 Bucket of the passed URL
        key: str
            S3 Key of the passed URL
        """
        path_parts = s3_path.replace("s3://", "").split("/")
        bucket = path_parts.pop(0)
        key = "/".join(path_parts)

        return bucket, key


def lambda_handler(event, context):
    """This is a sample Annotation Consolidation Lambda for custom labeling jobs. It takes all worker responses for the
    item to be labeled, and output a consolidated annotation.
    Parameters
    ----------
    event: dict, required
        Content of an example event
        {
            "version": "2018-10-16",
            "labelingJobArn": <labelingJobArn>,
            "labelCategories": [<string>],  # If you created labeling job using aws console, labelCategories will be null
            "labelAttributeName": <string>,
            "roleArn" : "string",
            "payload": {
                "s3Uri": <string>
            }
            "outputConfig":"s3://<consolidated_output configured for labeling job>"
         }
        Content of payload.s3Uri
        [
            {
                "datasetObjectId": <string>,
                "dataObject": {
                    "s3Uri": <string>,
                    "content": <string>
                },
                "annotations": [{
                    "workerId": <string>,
                    "annotationData": {
                        "content": <string>,
                        "s3Uri": <string>
                    }
               }]
            }
        ]
        As SageMaker product evolves, content of event object & payload.s3Uri will change. For a latest version refer following URL
        Event doc: https://docs.aws.amazon.com/sagemaker/latest/dg/sms-custom-templates-step3.html
    context: object, required
        Lambda Context runtime methods and attributes
        Context doc: https://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html
    Returns
    ------
    consolidated_output: dict
        AnnotationConsolidation
        [
           {
                "datasetObjectId": <string>,
                "consolidatedAnnotation": {
                    "content": {
                        "<labelattributename>": {
                            # ... label content
                        }
                    }
                }
            }
        ]
        Return doc: https://docs.aws.amazon.com/sagemaker/latest/dg/sms-custom-templates-step3.html
    """

    # Event received
    print("Running GT post-annotation lambda")
    debug("Received event: " + json.dumps(event, indent=2))

    labeling_job_arn = event["labelingJobArn"]
    label_attribute_name = event["labelAttributeName"]

    label_categories = None
    if "label_categories" in event:
        label_categories = event["labelCategories"]

    payload = event["payload"]
    role_arn = event["roleArn"]

    output_config = None  # Output s3 location. You can choose to write your annotation to this location
    if "outputConfig" in event:
        output_config = event["outputConfig"]

    # If you specified a KMS key in your labeling job, you can use the key to write
    # consolidated_output to s3 location specified in outputConfig.
    kms_key_id = None
    if "kmsKeyId" in event:
        kms_key_id = event["kmsKeyId"]

    # Create s3 client object
    s3_client = S3Client(role_arn, kms_key_id)

    # Perform consolidation
    return do_consolidation(labeling_job_arn, payload, label_attribute_name, s3_client)


def do_consolidation(labeling_job_arn, payload, label_attribute_name, s3_client):
    """
        Core Logic for consolidation
    :param labeling_job_arn: labeling job ARN
    :param payload:  payload data for consolidation
    :param label_attribute_name: identifier for labels in output JSON
    :param s3_client: S3 helper class
    :return: output JSON string
    """

    # Extract payload data
    if "s3Uri" in payload:
        s3_ref = payload["s3Uri"]
        payload = json.loads(s3_client.get_object_from_s3(s3_ref))

    # Payload data contains a list of data objects.
    # Iterate over it to consolidate annotations for individual data object.
    consolidated_output = []
    success_count = 0  # Number of data objects that were successfully consolidated
    failure_count = 0  # Number of data objects that failed in consolidation

    for p in range(len(payload)):
        response = None
        try:
            dataset_object_id = payload[p]["datasetObjectId"]
            log_prefix = "[{}] data object id [{}] :".format(
                labeling_job_arn, dataset_object_id
            )
            debug("{} Consolidating annotations BEGIN ".format(log_prefix))

            annotations = payload[p]["annotations"]
            debug(
                "{} Received Annotations from all workers {}".format(
                    log_prefix, annotations
                )
            )

            # Iterate over annotations. Log all annotation to your CloudWatch logs
            for i in range(len(annotations)):
                worker_id = annotations[i]["workerId"]
                annotation_content = annotations[i]["annotationData"].get("content")
                annotation_s3_uri = annotations[i]["annotationData"].get("s3uri")
                annotation = (
                    annotation_content
                    if annotation_s3_uri is None
                    else s3_client.get_object_from_s3(annotation_s3_uri)
                )
                annotation_from_single_worker = json.loads(annotation)

                debug(
                    "{} Received Annotations from worker [{}] is [{}]".format(
                        log_prefix, worker_id, annotation_from_single_worker
                    )
                )

            # Notice that, no consolidation is performed, worker responses are combined and appended to final output
            # You can put your consolidation logic here
            consolidated_annotation = {
                "annotationsFromAllWorkers": annotations
            }  # TODO : Add your consolidation logic

            # Build consolidation response object for an individual data object
            response = {
                "datasetObjectId": dataset_object_id,
                "consolidatedAnnotation": {
                    "content": {label_attribute_name: consolidated_annotation}
                },
            }

            success_count += 1
            debug("{} Consolidating annotations END ".format(log_prefix))

            # Append individual data object response to the list of responses.
            if response is not None:
                consolidated_output.append(response)

        except:
            failure_count += 1
            debug(" Consolidation failed for dataobject {}".format(p))
            debug(" Unexpected error: Consolidation failed." + str(sys.exc_info()[0]))

    debug(
        "Consolidation Complete. Success Count {}  Failure Count {}".format(
            success_count, failure_count
        )
    )

    debug(" -- Consolidated Output -- ")
    debug(consolidated_output)
    debug(" ------------------------- ")
    return consolidated_output