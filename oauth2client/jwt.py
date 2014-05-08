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

"""A service account credentials class.

This credentials class is implemented on top of rsa library.
"""

__author__ = 'orest@google.com (Orest Bolohan)'

import base64
import rsa
import time
import types

from oauth2client import util
from oauth2client.anyjson import simplejson
from oauth2client.client import AssertionCredentials

from pyasn1.codec.ber import decoder
from pyasn1_modules.rfc5208 import PrivateKeyInfo


class ServiceAccountCredentials(AssertionCredentials):
  """Class representing a service account (signed JWT) credential."""

  GOOGLE_REVOKE_URI = 'https://accounts.google.com/o/oauth2/revoke'
  GOOGLE_TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'

  MAX_TOKEN_LIFETIME_SECS = 3600 # 1 hour in seconds

  def __init__(self,
      service_account_name,
      private_key_id,
      private_key,
      scope,
      user_agent=None,
      token_uri=GOOGLE_TOKEN_URI,
      revoke_uri=GOOGLE_REVOKE_URI,
      **kwargs):

    super(ServiceAccountCredentials, self).__init__(
        None,
        user_agent=user_agent,
        token_uri=token_uri,
        revoke_uri=revoke_uri)
    
    self._service_account_name = service_account_name
    self._private_key_id = private_key_id
    self._private_key = _get_pk(private_key)
    self._raw_private_key = private_key
    self._scope = util.scopes_to_string(scope)
    self._user_agent = user_agent
    self._token_uri = token_uri
    self._revoke_uri = revoke_uri
    self._kwargs = kwargs

  def _generate_assertion(self):
    """Generate the assertion that will be used in the request."""

    header = {
        'alg': 'RS256',
        'typ': 'JWT',
        'keyid': self._private_key_id
    }

    now = long(time.time())
    payload = {
        'aud': self._token_uri,
        'scope': self._scope,
        'iat': now,
        'exp': now + ServiceAccountCredentials.MAX_TOKEN_LIFETIME_SECS,
        'iss': self._service_account_name
    }
    payload.update(self._kwargs)

    assertion_input = '%s.%s' % (
        _urlsafe_b64encode(header),
        _urlsafe_b64encode(payload))

    # Sign the assertion.
    signature = base64.urlsafe_b64encode(rsa.pkcs1.sign(
        assertion_input, self._private_key, 'SHA-256')).rstrip('=')

    return '%s.%s' % (assertion_input, signature)

  def sign_blob(self, blob):
    return (self._private_key_id,
            rsa.pkcs1.sign(blob, self._private_key, 'SHA-256'))

  def get_service_account_name(self):
    return self._service_account_name

  def scopes_required(self):
    return not bool(self._scope)

  def create_scoped(self, scopes):
    return ServiceAccountCredentials(self._service_account_name,
                                     self._private_key_id,
                                     self._raw_private_key,
                                     scopes,
                                     user_agent=self._user_agent,
                                     token_uri=self._token_uri,
                                     revoke_uri=self._revoke_uri,
                                     **self._kwargs)

def _urlsafe_b64encode(data):
  return base64.urlsafe_b64encode(
      simplejson.dumps(data, separators = (',', ':'))\
          .encode('UTF-8')).rstrip('=')

def _get_pk(private_key):
  """Get an RSA private key object from a pkcs8 representation."""

  der = rsa.pem.load_pem(private_key, 'PRIVATE KEY')
  asn1_private_key, _ = decoder.decode(der, asn1Spec=PrivateKeyInfo())
  return rsa.PrivateKey.load_pkcs1(
      asn1_private_key.getComponentByName('privateKey').asOctets(),
      format='DER')
