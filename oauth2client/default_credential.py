# Copyright (C) 2014 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Provides default Credentials to be used in authenticating Google APIs calls.

TODO(orest): add usage example here.
"""

__author__ = 'orest@google.com (Orest Bolohan)'

from os import environ

class GoogleCredential:
  """Conveniently wrap the the GetDefaultCredential method.
  
  This is to keep it in line with the Java implementation's idiom.
  """
  
  @staticmethod
  def GetDefaultCredential(scopes=[]):
    """Get the default credentials with the given scopes.""" 

    env_name = GetEnvironment()
    if env_name == 'GAE_PRODUCTION' or env_name == 'GAE_LOCAL':
      from oauth2client.appengine import AppAssertionCredentials

      return AppAssertionCredentials(scopes)
    elif environ.get('GOOGLE_CREDENTIALS_DEFAULT'):
      import jwt

      default_credential_file = environ.get('GOOGLE_CREDENTIALS_DEFAULT')

      # read the credentials from the file
      default_credential = open(default_credential_file)
      client_credentials = jwt.simplejson.load(default_credential)
      default_credential.close()

      if 'type' not in client_credentials:
        raise Exception("'type' field should be defined "
                        "(and have one of the 'authorized_user' "
                        "or 'service_account' values) in "
                        + default_credential_file)

      if client_credentials['type'] == 'authorized_user':
        missing_fields = []
        if 'client_id' not in client_credentials:
          missing_fields.append('client_id')
        if 'client_secret' not in client_credentials:
          missing_fields.append('client_secret')
        if 'refresh_token' not in client_credentials:
          missing_fields.append('refresh_token')
        if len(missing_fields) > 0:
          raise Exception("The following field(s): "
                          + ", ".join(missing_fields) + " must be defined in "
                          + default_credential_file)

        from oauth2client.client import OAuth2Credentials

        return OAuth2Credentials(
            None,
            client_credentials['client_id'],
            client_credentials['client_secret'],
            client_credentials['refresh_token'],
            None,
            'https://accounts.google.com/o/oauth2/token',
            'Python client library')
      elif client_credentials['type'] == 'service_account':
        missing_fields = []
        if 'client_email' not in client_credentials:
          missing_fields.append('client_email')
        if 'private_key' not in client_credentials:
          missing_fields.append('private_key')
        if len(missing_fields) > 0:
          raise Exception("The following field(s): "
                          + ", ".join(missing_fields) + " must be defined in "
                          + default_credential_file)

        return jwt.ServiceAccountCredentials(
            client_credentials['client_email'],
            client_credentials['private_key'],
            scopes)
      else:
        raise Exception("'type' field should have one of the "
                        "'authorized_user' or 'service_account' values "
                        "in " + default_credential_file)
    elif env_name == 'GCE_PRODUCTION':
      from oauth2client.gce import AppAssertionCredentials
    
      return AppAssertionCredentials(scopes)
    else:
      raise Exception('GOOGLE_CREDENTIALS_DEFAULT '
                      'environment variable must be set!')

def GetEnvironment():
  """Detect the environment the code is being run on."""

  server_software = environ.get('SERVER_SOFTWARE', '')
  if server_software.startswith('Google App Engine/'):
    return 'GAE_PRODUCTION'
  elif server_software.startswith('Development/'):
    return 'GAE_LOCAL'
  else:
    import socket
    try:
      socket.gethostbyname('metadata.google.internal')
      return 'GCE_PRODUCTION'
    except socket.gaierror:
      return 'UNKNOWN'