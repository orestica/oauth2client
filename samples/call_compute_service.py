# To be used to test GoogleCredential.GetDefaultCredential()
# from local machine and GCE.

from googleapiclient.discovery import build
from oauth2client.client import Credentials

PROJECT = "bamboo-machine-422"  # Provide your own GCE project here
ZONE = "us-central1-a"          # Put here a zone which has some VMs

service = build("compute", "v1", credentials=Credentials.get_default())

resource = service.instances()
request = resource.list(project=PROJECT, zone=ZONE)
response = request.execute()

print response
