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

import os

class GoogleCredential:
  """Conveniently wrap the the GetDefaultCredential method.
  
  This is to keep it in line with the Java implementation's idiom.
  """
  
  @staticmethod
  def GetDefaultCredential(scopes=[]):
    """Get the default credentials with the given scopes."""
    
    default_credential_file = os.environ.get('GOOGLE_CREDENTIALS_DEFAULT')
    well_known_file = GetWellKnownFile()
    env_name = GetEnvironment()

    if default_credential_file:
      return GetDefaultCredentialFromFile(default_credential_file, scopes)
    elif well_known_file:
      return GetDefaultCredentialFromFile(well_known_file, scopes)
    elif env_name == 'GAE_PRODUCTION' or env_name == 'GAE_LOCAL':
      return GetDefaultCredentialGAE(scopes)
    elif env_name == 'GCE_PRODUCTION':
      return GetDefaultCredentialGCE(scopes)
    else:
      raise Exception('Either GOOGLE_CREDENTIALS_DEFAULT '
                      'environment variable must be set or you need '
                      'to run "gcloud auth login"!')


def GetWellKnownFile():
  """Get the well known file produced by command 'gcloud auth login'."""
  
  WELL_KNOWN_CREDENTIALS_FILE = "credentials_default.json"
  CLOUDSDK_CONFIG_WORD = "gcloud"
  
  if os.name == 'nt':
    try:
      default_config_path = os.path.join(
          os.environ['APPDATA'], CLOUDSDK_CONFIG_WORD)
    except KeyError:
      # This should never happen unless someone is really messing with things.
      drive = os.environ.get('SystemDrive', 'C:')
      default_config_path = os.path.join(
          drive, '\\', CLOUDSDK_CONFIG_WORD)
  else:
    default_config_path = os.path.join(
        os.path.expanduser('~'), '.config', CLOUDSDK_CONFIG_WORD)
    
  default_config_path = os.path.join(default_config_path,
      WELL_KNOWN_CREDENTIALS_FILE)
  
  if os.path.isfile(default_config_path):
    return default_config_path
  else:
    None


def GetEnvironment():
  """Detect the environment the code is being run on."""

  server_software = os.environ.get('SERVER_SOFTWARE', '')
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


def GetDefaultCredentialFromFile(default_credential_file, scopes):
  """Build the default credentials from file."""
  
  import jwt

  if not os.path.isfile(default_credential_file):
    raise Exception('File ' + default_credential_file + ' does not exist!')

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


def GetDefaultCredentialGAE(scopes):
  from oauth2client.appengine import AppAssertionCredentials

  return AppAssertionCredentials(scopes)


def GetDefaultCredentialGCE(scopes):
  from oauth2client.gce import AppAssertionCredentials

  return AppAssertionCredentials(scopes)
