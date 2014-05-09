#!/usr/bin/python2.4
#
# Copyright 2014 Google Inc.
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


"""Oauth2client tests

Unit tests for service account credentials implemented using RSA.
"""

__author__ = 'orest@google.com (Orest Bolohan)'

import os
import rsa
import time
import unittest

from http_mock import HttpMockSequence
from oauth2client.anyjson import simplejson
from oauth2client.jwt import ServiceAccountCredentials


def datafile(filename):
  f = open(os.path.join(os.path.dirname(__file__), 'data', filename), 'r')
  data = f.read()
  f.close()
  return data


class ServiceAccountCredentialsTests(unittest.TestCase):
  def setUp(self):
    self.service_account_name = 'dummy@google.com'
    self.private_key_id = 'ABCDEF'
    self.private_key = datafile('pem_from_pkcs12.pem')
    self.scopes = ['dummy_scope']
    self.credentials = ServiceAccountCredentials(self.service_account_name,
                                                 self.private_key_id,
                                                 self.private_key,
                                                 [])

  def test_sign_blob(self):
    private_key_id, signature = self.credentials.sign_blob('Google')
    self.assertEqual( self.private_key_id, private_key_id)

    pub_key = rsa.PublicKey.load_pkcs1_openssl_pem(
        datafile('publickey_openssl.pem'))

    self.assertTrue(rsa.pkcs1.verify('Google', signature, pub_key))

    try:
      rsa.pkcs1.verify('Orest', signature, pub_key)
      self.fail('Verification should have failed!')
    except rsa.pkcs1.VerificationError:
      pass  # Expected

    try:
      rsa.pkcs1.verify('Google', 'bad signature', pub_key)
      self.fail('Verification should have failed!')
    except rsa.pkcs1.VerificationError:
      pass  # Expected

  def test_get_service_account_name(self):
    self.assertEqual(self.service_account_name,
                     self.credentials.get_service_account_name())

  def test_scopes_required_without_scopes(self):
    self.assertTrue(self.credentials.scopes_required())

  def test_scopes_required_with_scopes(self):
    self.credentials = ServiceAccountCredentials(self.service_account_name,
                                                 self.private_key_id,
                                                 self.private_key,
                                                 self.scopes)
    self.assertFalse(self.credentials.scopes_required())

  def test_create_scoped(self):
    new_credentials = self.credentials.create_scoped(self.scopes)
    self.assertNotEqual(self.credentials, new_credentials)
    #self.assertIsInstance(new_credentials, ServiceAccountCredentials)
    self.assertEqual('dummy_scope', new_credentials._scope)

  def test_access_token(self):
    token_response_first = {'access_token': 'first_token', 'expires_in': 1}
    token_response_second = {'access_token': 'second_token', 'expires_in': 1}
    http = HttpMockSequence([
        ({'status': '200'}, simplejson.dumps(token_response_first)),
        ({'status': '200'}, simplejson.dumps(token_response_second)),
    ])
  
    self.assertEqual('first_token',
                     self.credentials.get_access_token(http=http))
    self.assertFalse(self.credentials.access_token_expired)
    self.assertEqual(token_response_first, self.credentials.token_response)

    self.assertEqual('first_token',
                     self.credentials.get_access_token(http=http))
    self.assertFalse(self.credentials.access_token_expired)
    self.assertEqual(token_response_first, self.credentials.token_response)

    time.sleep(1)
    self.assertTrue(self.credentials.access_token_expired)

    self.assertEqual('second_token',
                     self.credentials.get_access_token(http=http))
    self.assertFalse(self.credentials.access_token_expired)
    self.assertEqual(token_response_second, self.credentials.token_response)
