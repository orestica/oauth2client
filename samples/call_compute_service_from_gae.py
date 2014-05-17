# To be used to test GoogleCredential.GetDefaultCredential()
# from devel GAE (ie, dev_appserver.py).

import webapp2
from googleapiclient.discovery import build
from oauth2client.default_credential import GoogleCredential

PROJECT = "bamboo-machine-422"  # Provide your own GCE project here
ZONE = "us-central1-a"          # Put here a zone which has some VMs

def get_instances():
  service = build("compute", "v1",
      credentials=GoogleCredential.get_default_credential())
  resource = service.instances()
  request = resource.list(project=PROJECT, zone=ZONE)
  return request.execute()

class MainPage(webapp2.RequestHandler):

  def get(self):
    self.response.write(get_instances())

app = webapp2.WSGIApplication([
  ('/', MainPage),
], debug=True)
