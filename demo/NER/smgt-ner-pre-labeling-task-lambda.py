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


def lambda_handler(event, context):
    """
    Sagemaker Groundtruth pre-processing pass-through lambda
    ----------
    Given an input manifest that looks like:

        {"source": "{\"question\": \"What is 9 times 4?\"}"}
        {"source": "{\"question\": \"What is 8 divided by 4?\"}"}
        {"source": "{\"question\": \"What is 101 minus 12?\"}"}

    The `event` argument will look like:
    event: dict, required

        {
           "version":"2018-10-16",
           "labelingJobArn":"<your labeling job ARN>",
           "dataObject":{
              "source": "{\"question\": \"What is 9 times 4?\"}"
           }
        }

    context: object, required
        Context doc: https://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html

    Returns
    ------
    output: dict
        This output is passed to the Sagemaker Ground Truth custom UI template.
        Additional parameters can be added under "taskInput" if needed.
        {
           "taskInput":{
              "source": {
                  "question": "What is 9 times 4?"
              }
           },
           "isHumanAnnotationRequired":true
        }

    SM:GT Preprocessing documentation:
    Return doc: https://docs.aws.amazon.com/sagemaker/latest/dg/sms-custom-templates-step3.html
    """

    # Event received
    print("Running GT pre-annotation lambda")
    # Uncomment this statement to log the incoming event to cloudwatch
    # print("SM:GT Preprocessing lambda received event: " + json.dumps(event, indent=4))
    task_input = json.loads(event["dataObject"]["source"])

    # Response object
    output = {"taskInput": task_input, "isHumanAnnotationRequired": "true"}

    # Uncomment this statement to log output to cloudwatch
    # print(
    #    "SM:GT Preprocessing lambda sending payload to worker user interface:",
    #    json.dumps(output, indent=4),
    # )

    return output