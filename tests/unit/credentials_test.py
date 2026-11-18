# -*- coding: utf-8 -*-
# MinIO Python Library for Amazon S3 Compatible Cloud Storage, (C)
# [2014] - [2025] MinIO, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest import TestCase
from unittest.mock import MagicMock, patch

from urllib3.poolmanager import PoolManager
from urllib3.util.ssl_ import create_urllib3_context

from minio.credentials.providers import (AWSConfigProvider, ChainedProvider,
                                         EnvAWSProvider, EnvMinioProvider,
                                         IamAwsProvider,
                                         MinioClientConfigProvider,
                                         StaticProvider,
                                         _http_client_with_ca_bundle)

from .minio_mocks import MockResponse

CONFIG_JSON_SAMPLE = "tests/unit/config.json.sample"
CREDENTIALS_SAMPLE = "tests/unit/credentials.sample"
CREDENTIALS_EMPTY = "tests/unit/credentials.empty"


class CredentialsTest(TestCase):
    def test_credentials_get(self):
        provider = MinioClientConfigProvider(
            filename=CONFIG_JSON_SAMPLE,
            alias="play",
        )
        creds = provider.retrieve()
        self.assertEqual(creds.access_key, "Q3AM3UQ867SPQQA43P2F")
        self.assertEqual(creds.secret_key,
                         "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG")
        self.assertEqual(creds.session_token, None)


class ChainedProviderTest(TestCase):
    def test_chain_retrieve(self):
        # clear environment
        os.environ.clear()
        # prepare env for env_aws provider
        os.environ["AWS_ACCESS_KEY_ID"] = "access_aws"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "secret_aws"
        os.environ["AWS_SESSION_TOKEN"] = "token_aws"
        # prepare env for env_minio
        os.environ["MINIO_ACCESS_KEY"] = "access_minio"
        os.environ["MINIO_SECRET_KEY"] = "secret_minio"
        # create chain provider with env_aws and env_minio providers

        provider = ChainedProvider(
            [
                EnvAWSProvider(), EnvMinioProvider(),
            ]
        )
        # retrieve provider (env_aws) has priority
        creds = provider.retrieve()
        # assert provider credentials
        self.assertEqual(creds.access_key, "access_aws")
        self.assertEqual(creds.secret_key, "secret_aws")
        self.assertEqual(creds.session_token, "token_aws")

    def test_chain_retrieve_failed_provider(self):
        # clear environment
        os.environ.clear()
        # prepare env for env_minio
        os.environ["MINIO_ACCESS_KEY"] = "access_minio"
        os.environ["MINIO_SECRET_KEY"] = "secret_minio"
        # create chain provider with env_aws and env_minio providers

        provider = ChainedProvider(
            [
                EnvAWSProvider(), EnvMinioProvider(),
            ]
        )
        # retrieve provider: (env_minio) will be retrieved
        creds = provider.retrieve()
        # assert provider credentials
        self.assertEqual(creds.access_key, "access_minio")
        self.assertEqual(creds.secret_key, "secret_minio")
        self.assertEqual(creds.session_token, None)


class EnvAWSProviderTest(TestCase):
    def test_env_aws_retrieve(self):
        os.environ.clear()
        os.environ["AWS_ACCESS_KEY_ID"] = "access"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "secret"
        os.environ["AWS_SESSION_TOKEN"] = "token"
        provider = EnvAWSProvider()
        creds = provider.retrieve()
        self.assertEqual(creds.access_key, "access")
        self.assertEqual(creds.secret_key, "secret")
        self.assertEqual(creds.session_token, "token")

    def test_env_aws_retrieve_no_token(self):
        os.environ.clear()
        os.environ["AWS_ACCESS_KEY_ID"] = "access"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "secret"
        provider = EnvAWSProvider()
        creds = provider.retrieve()
        self.assertEqual(creds.access_key, "access")
        self.assertEqual(creds.secret_key, "secret")
        self.assertEqual(creds.session_token, None)


class EnvMinioTest(TestCase):
    def test_env_minio_retrieve(self):
        os.environ.clear()
        os.environ['MINIO_ACCESS_KEY'] = "access"
        os.environ["MINIO_SECRET_KEY"] = "secret"
        provider = EnvMinioProvider()
        creds = provider.retrieve()
        self.assertEqual(creds.access_key, "access")
        self.assertEqual(creds.secret_key, "secret")
        self.assertEqual(creds.session_token, None)


class AWSConfigProviderTest(TestCase):
    def test_file_aws(self):
        os.environ.clear()
        provider = AWSConfigProvider(CREDENTIALS_SAMPLE)
        creds = provider.retrieve()
        self.assertEqual(creds.access_key, "accessKey")
        self.assertEqual(creds.secret_key, "secret")
        self.assertEqual(creds.session_token, "token")

    def test_file_aws_from_env(self):
        os.environ.clear()
        os.environ["AWS_SHARED_CREDENTIALS_FILE"] = (
            CREDENTIALS_SAMPLE
        )
        provider = AWSConfigProvider()
        creds = provider.retrieve()
        self.assertEqual(creds.access_key, "accessKey")
        self.assertEqual(creds.secret_key, "secret")
        self.assertEqual(creds.session_token, "token")

    def test_file_aws_env_profile(self):
        os.environ.clear()
        os.environ["AWS_PROFILE"] = "no_token"
        provider = AWSConfigProvider(CREDENTIALS_SAMPLE)
        creds = provider.retrieve()
        self.assertEqual(creds.access_key, "accessKey")
        self.assertEqual(creds.secret_key, "secret")
        self.assertEqual(creds.session_token, None)

    def test_file_aws_arg_profile(self):
        os.environ.clear()
        provider = AWSConfigProvider(
            CREDENTIALS_SAMPLE,
            "no_token",
        )
        creds = provider.retrieve()
        self.assertEqual(creds.access_key, "accessKey")
        self.assertEqual(creds.secret_key, "secret")
        self.assertEqual(creds.session_token, None)

    def test_file_aws_no_creds(self):
        os.environ.clear()
        provider = AWSConfigProvider(
            CREDENTIALS_EMPTY,
            "no_token",
        )
        try:
            provider.retrieve()
        except ValueError:
            pass


class MinioClientConfigProviderTest(TestCase):
    def test_file_minio_(self):
        os.environ.clear()
        provider = MinioClientConfigProvider(filename=CONFIG_JSON_SAMPLE)
        creds = provider.retrieve()
        self.assertEqual(creds.access_key, "accessKey")
        self.assertEqual(creds.secret_key, "secret")
        self.assertEqual(creds.session_token, None)

    def test_file_minio_env_alias(self):
        os.environ.clear()
        os.environ["MINIO_ALIAS"] = "play"
        provider = MinioClientConfigProvider(filename=CONFIG_JSON_SAMPLE)
        creds = provider.retrieve()
        self.assertEqual(creds.access_key, "Q3AM3UQ867SPQQA43P2F")
        self.assertEqual(creds.secret_key,
                         "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG")
        self.assertEqual(creds.session_token, None)

    def test_file_minio_arg_alias(self):
        os.environ.clear()
        provider = MinioClientConfigProvider(
            filename=CONFIG_JSON_SAMPLE,
            alias="play",
        )
        creds = provider.retrieve()
        self.assertEqual(creds.access_key, "Q3AM3UQ867SPQQA43P2F")
        self.assertEqual(creds.secret_key,
                         "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG")
        self.assertEqual(creds.session_token, None)


class StaticProviderTest(TestCase):
    def test_static_credentials(self):
        provider = StaticProvider("UXHW", "SECRET")
        creds = provider.retrieve()
        self.assertEqual(creds.access_key, "UXHW")
        self.assertEqual(creds.secret_key, "SECRET")
        self.assertEqual(creds.session_token, None)


IMDS_CREDENTIALS = (
    b'{"AccessKeyId": "a", "SecretAccessKey": "s", '
    b'"Token": "t", "Expiration": "2030-01-01T00:00:00Z"}'
)

STS_RESPONSE = b"""<AssumeRoleWithWebIdentityResponse>
<AssumeRoleWithWebIdentityResult><Credentials>
<AccessKeyId>access</AccessKeyId><SecretAccessKey>secret</SecretAccessKey>
<SessionToken>token</SessionToken>
<Expiration>2030-01-01T00:00:00Z</Expiration>
</Credentials></AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"""


class _IamAwsEnvTestCase(TestCase):
    """Base: web-identity environment with a token file."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.token_file = os.path.join(self._tmp.name, "token")
        with open(self.token_file, "w", encoding="utf-8") as file:
            file.write("jwt")
        env = patch.dict(os.environ, {
            "AWS_WEB_IDENTITY_TOKEN_FILE": self.token_file,
            "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/example",
        })
        env.start()
        self.addCleanup(env.stop)
        for name in (
                "AWS_ENDPOINT_URL_STS", "AWS_ENDPOINT_URL",
                "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "AWS_CA_BUNDLE",
                "AWS_REGION", "SSL_CERT_FILE",
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        ):
            os.environ.pop(name, None)


class IamAwsProviderStsEndpointTest(_IamAwsEnvTestCase):
    """Test STS endpoint resolution of IamAwsProvider."""

    def _sts_endpoint(self, **kwargs):
        """Retrieve with WebIdentityProvider stubbed; no network."""
        with patch(
                "minio.credentials.providers.WebIdentityProvider",
        ) as web_identity:
            IamAwsProvider(**kwargs).retrieve()
        return web_identity.call_args.kwargs["sts_endpoint"]

    def test_t1_explicit_endpoint_wins(self):
        os.environ["AWS_ENDPOINT_URL_STS"] = "https://sts.example.com"
        os.environ["AWS_ENDPOINT_URL"] = "https://generic.example.com"
        self.assertEqual(
            self._sts_endpoint(custom_endpoint="https://custom.example.com"),
            "https://custom.example.com",
        )

    def test_t2_global_endpoint_url_ignored(self):
        os.environ["AWS_ENDPOINT_URL"] = "https://generic.example.com"
        self.assertEqual(self._sts_endpoint(), "https://sts.amazonaws.com")
        os.environ["AWS_ENDPOINT_URL_STS"] = ""  # empty counts as unset
        self.assertEqual(self._sts_endpoint(), "https://sts.amazonaws.com")

    def test_t3_ca_bundle_ignored_without_sts_env(self):
        os.environ["AWS_CA_BUNDLE"] = os.path.join(self._tmp.name, "missing")
        self.assertEqual(self._sts_endpoint(), "https://sts.amazonaws.com")
        self.assertEqual(
            self._sts_endpoint(custom_endpoint="https://custom.example.com"),
            "https://custom.example.com",
        )
        os.environ["AWS_ENDPOINT_URL_STS"] = "https://sts.example.com"
        self.assertEqual(
            self._sts_endpoint(custom_endpoint="https://custom.example.com"),
            "https://custom.example.com",
        )

    def test_t4_endpoint_url_sts_over_region_default(self):
        os.environ["AWS_REGION"] = "eu-west-1"
        os.environ["AWS_ENDPOINT_URL_STS"] = "https://sts.example.com"
        self.assertEqual(self._sts_endpoint(), "https://sts.example.com")

    def test_t5_ignore_flag_true_selects_default_host(self):
        os.environ["AWS_REGION"] = "eu-west-1"
        os.environ["AWS_ENDPOINT_URL_STS"] = "https://sts.example.com"
        os.environ["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
        self.assertEqual(
            self._sts_endpoint(), "https://sts.eu-west-1.amazonaws.com",
        )
        del os.environ["AWS_REGION"]
        self.assertEqual(self._sts_endpoint(), "https://sts.amazonaws.com")

    def test_t5_ignore_flag_keeps_explicit_endpoint(self):
        os.environ["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
        self.assertEqual(
            self._sts_endpoint(custom_endpoint="https://custom.example.com"),
            "https://custom.example.com",
        )

    def test_t6_ignore_flag_case_and_false(self):
        os.environ["AWS_ENDPOINT_URL_STS"] = "https://sts.example.com"
        os.environ["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "TRUE"
        self.assertEqual(self._sts_endpoint(), "https://sts.amazonaws.com")
        os.environ["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "false"
        self.assertEqual(self._sts_endpoint(), "https://sts.example.com")

    def test_t7_path_preserved(self):
        os.environ["AWS_ENDPOINT_URL_STS"] = (
            "https://sts.example.com/sts/ns/name"
        )
        self.assertEqual(
            self._sts_endpoint(), "https://sts.example.com/sts/ns/name",
        )
        with patch(
                "minio.credentials.providers.PoolManager.urlopen",
                autospec=True,
                return_value=MockResponse(
                    "POST", "", {}, 200, content=STS_RESPONSE,
                ),
        ) as urlopen:
            IamAwsProvider().retrieve()
        self.assertTrue(urlopen.call_args.args[2].startswith(
            "https://sts.example.com/sts/ns/name?",
        ), urlopen.call_args.args[2])

    def test_t8_imds_ignores_env(self):
        del os.environ["AWS_WEB_IDENTITY_TOKEN_FILE"]
        os.environ["AWS_ENDPOINT_URL_STS"] = "https://sts.example.com"
        os.environ["AWS_ENDPOINT_URL"] = "https://generic.example.com"
        os.environ["AWS_CA_BUNDLE"] = "/nonexistent/bundle.pem"
        http_client = MagicMock()
        http_client.urlopen.side_effect = [
            MockResponse("PUT", "", {}, 200, content=b"token"),
            MockResponse("GET", "", {}, 200, content=b"role"),
            MockResponse("GET", "", {}, 200, content=IMDS_CREDENTIALS),
        ]
        creds = IamAwsProvider(http_client=http_client).retrieve()
        self.assertEqual(creds.access_key, "a")
        urls = [call.args[1] for call in http_client.urlopen.call_args_list]
        self.assertTrue(all(
            url.startswith("http://169.254.169.254") for url in urls
        ), urls)
        # IMDS path without a caller client must not read the bundle either.
        with patch("minio.credentials.providers._urlopen") as urlopen:
            urlopen.side_effect = [
                MockResponse("PUT", "", {}, 200, content=b"token"),
                MockResponse("GET", "", {}, 200, content=b"role"),
                MockResponse("GET", "", {}, 200, content=IMDS_CREDENTIALS),
            ]
            IamAwsProvider().retrieve()
        for call in urlopen.call_args_list:
            self.assertTrue(call.args[2].startswith("http://169.254.169.254"))

    def test_t14_cn_region_default(self):
        os.environ["AWS_REGION"] = "cn-north-1"
        self.assertEqual(
            self._sts_endpoint(), "https://sts.cn-north-1.amazonaws.com.cn",
        )

    def test_default_region_not_aws_default_region(self):
        os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"
        try:
            self.assertEqual(self._sts_endpoint(), "https://sts.amazonaws.com")
        finally:
            del os.environ["AWS_DEFAULT_REGION"]


def _handshake(client_context, server_context, hostname="localhost"):
    """Run a TLS handshake in memory, without sockets."""
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    sides = [
        client_context.wrap_bio(
            client_in, client_out, server_hostname=hostname,
        ),
        server_context.wrap_bio(server_in, server_out, server_side=True),
    ]
    done = [False, False]
    for _ in range(50):
        for index, side in enumerate(sides):
            if not done[index]:
                try:
                    side.do_handshake()
                    done[index] = True
                except ssl.SSLWantReadError:
                    pass
        server_in.write(client_out.read())
        client_in.write(server_out.read())
        if all(done):
            return
    raise AssertionError("TLS handshake did not complete")


@unittest.skipUnless(shutil.which("openssl"), "openssl is required")
class IamAwsProviderCABundleTest(_IamAwsEnvTestCase):
    """Test AWS_CA_BUNDLE with in-memory TLS handshakes; no sockets."""

    def setUp(self):
        super().setUp()
        self.cert = os.path.join(self._tmp.name, "cert.pem")
        self.key = os.path.join(self._tmp.name, "key.pem")
        self._make_cert(self.cert, self.key)
        os.environ["AWS_ENDPOINT_URL_STS"] = "https://sts.example.com"

    def _make_cert(self, cert, key, san=True):
        """Generate self-signed cert; a config file works on any OpenSSL."""
        conf = cert + ".cnf"
        lines = [
            "[req]", "distinguished_name=dn", "prompt=no",
            "x509_extensions=ext", "[dn]", "CN=localhost", "[ext]",
            "basicConstraints=critical,CA:TRUE",
        ]
        if san:
            lines.append("subjectAltName=DNS:localhost,IP:127.0.0.1")
        with open(conf, "w", encoding="utf-8") as file:
            file.write("\n".join(lines) + "\n")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-config", conf, "-keyout", key, "-out", cert,
            ],
            check=True, capture_output=True,
        )

    @staticmethod
    def _server_context(cert, key):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        return context

    def _retrieve(self, **kwargs):
        """Retrieve with mocked STS HTTP exchange; return pool and creds."""
        pools = []

        def urlopen(pool, method, url, *args, **kwargs):
            pools.append(pool)
            return MockResponse(
                method, url, {}, 200, content=STS_RESPONSE,
            )

        with patch(
                "minio.credentials.providers.PoolManager.urlopen",
                autospec=True, side_effect=urlopen,
        ):
            creds = IamAwsProvider(**kwargs).retrieve()
        self.assertEqual(creds.access_key, "access")
        return pools[0]

    def _client_context(self):
        pool = self._retrieve()
        return pool.connection_pool_kw["ssl_context"]

    def test_t9_ca_bundle_trusted(self):
        os.environ["AWS_CA_BUNDLE"] = self.cert
        context = self._client_context()
        context.check_hostname = True
        _handshake(context, self._server_context(self.cert, self.key))

    def test_t10_without_ca_bundle_fails(self):
        pool = self._retrieve()
        self.assertNotIn("ssl_context", pool.connection_pool_kw)
        context = create_urllib3_context()
        context.load_default_certs()
        with self.assertRaises(ssl.SSLCertVerificationError):
            _handshake(context, self._server_context(self.cert, self.key))

    def test_b6_bundle_added_to_existing_trust(self):
        """Server cert trusted via SSL_CERT_FILE stays trusted with bundle."""
        other = os.path.join(self._tmp.name, "other.pem")
        self._make_cert(other, os.path.join(self._tmp.name, "other.key"))
        os.environ["SSL_CERT_FILE"] = self.cert
        os.environ["AWS_CA_BUNDLE"] = other
        _handshake(
            self._client_context(), self._server_context(self.cert, self.key),
        )

    def test_bundle_keeps_urllib3_hostname_policy(self):
        """Bundle context uses the installed urllib3's hostname policy."""
        os.environ["AWS_CA_BUNDLE"] = self.cert
        context = self._client_context()
        self.assertEqual(
            getattr(context, "hostname_checks_common_name", None),
            getattr(
                create_urllib3_context(), "hostname_checks_common_name", None,
            ),
        )
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_bundle_read_once(self):
        """The validated bundle is the bundle used: it is opened once."""
        os.environ["AWS_CA_BUNDLE"] = self.cert
        opened = []
        real_open = open

        def spy(file, *args, **kwargs):
            opened.append(file)
            return real_open(file, *args, **kwargs)

        load = ssl.SSLContext.load_verify_locations
        cafiles = []

        def spy_load(context, *args, **kwargs):
            cafiles.append(kwargs.get("cafile"))
            return load(context, *args, **kwargs)

        with patch("builtins.open", spy), patch.object(
                ssl.SSLContext, "load_verify_locations", spy_load):
            self._client_context()
        self.assertEqual(opened.count(self.cert), 1)
        self.assertNotIn(self.cert, cafiles)

    def test_bundle_check_independent_of_tls_backend(self):
        """Contexts without ssl.SSLContext methods (pyOpenSSL) still work."""
        os.environ["AWS_CA_BUNDLE"] = self.cert

        class _BackendContext:  # pylint: disable=too-few-public-methods
            loaded = []

            def load_verify_locations(self, **kwargs):
                """Record loads."""
                self.loaded.append(kwargs)

            def set_default_verify_paths(self):
                """Record loads."""
                self.loaded.append("default")

        with patch(
                "minio.credentials.providers.create_urllib3_context",
                _BackendContext,
        ), patch("minio.credentials.providers.PoolManager") as pool:
            _http_client_with_ca_bundle(self.cert)
        self.assertIs(
            type(pool.call_args.kwargs["ssl_context"]), _BackendContext,
        )
        self.assertEqual(_BackendContext.loaded[-1], "default")

    def test_t11_custom_client_untouched(self):
        os.environ["AWS_CA_BUNDLE"] = self.cert
        http_client = PoolManager()
        before = dict(http_client.connection_pool_kw)
        with patch.object(
                http_client, "urlopen",
                return_value=MockResponse(
                    "POST", "", {}, 200, content=STS_RESPONSE,
                ),
        ) as urlopen:
            IamAwsProvider(http_client=http_client).retrieve()
        urlopen.assert_called_once()
        self.assertEqual(http_client.connection_pool_kw, before)

    def _assert_bundle_rejected(self):
        """Provider fails locally, before any STS request."""
        with patch(
                "minio.credentials.providers.PoolManager.urlopen",
                autospec=True,
                return_value=MockResponse(
                    "POST", "", {}, 200, content=STS_RESPONSE,
                ),
        ) as urlopen:
            with self.assertRaisesRegex(ValueError, "AWS_CA_BUNDLE"):
                IamAwsProvider().retrieve()
        urlopen.assert_not_called()

    def test_bundle_with_pyopenssl_backend(self):
        """A real injected pyOpenSSL context trusts the bundle."""
        try:
            # pylint: disable=import-outside-toplevel
            from OpenSSL import SSL
            from urllib3.contrib import pyopenssl
        except ImportError:
            self.skipTest("pyOpenSSL is not installed")
        os.environ["AWS_CA_BUNDLE"] = self.cert
        pyopenssl.inject_into_urllib3()
        self.addCleanup(pyopenssl.extract_from_urllib3)
        context = self._client_context()
        self.assertIsInstance(context, pyopenssl.PyOpenSSLContext)
        # In-memory handshake: pyOpenSSL client, standard-library server.
        # pylint: disable=protected-access
        client = SSL.Connection(context._ctx, None)
        client.set_connect_state()
        client.set_tlsext_host_name(b"localhost")
        server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        server = self._server_context(self.cert, self.key).wrap_bio(
            server_in, server_out, server_side=True,
        )
        done = [False, False]
        for _ in range(50):
            if not done[0]:
                try:
                    client.do_handshake()
                    done[0] = True
                except SSL.WantReadError:
                    pass
            if not done[1]:
                try:
                    server.do_handshake()
                    done[1] = True
                except ssl.SSLWantReadError:
                    pass
            try:
                server_in.write(client.bio_read(65536))
            except SSL.WantReadError:
                pass
            data = server_out.read()
            if data:
                client.bio_write(data)
            if all(done):
                break
        self.assertTrue(all(done), "TLS handshake did not complete")

    def test_t12_missing_bundle(self):
        os.environ["AWS_CA_BUNDLE"] = os.path.join(self._tmp.name, "missing")
        self._assert_bundle_rejected()

    def test_t13_bundle_without_certificates(self):
        bundle = os.path.join(self._tmp.name, "empty.pem")
        with open(bundle, "w", encoding="utf-8") as file:
            file.write("not a certificate\n")
        os.environ["AWS_CA_BUNDLE"] = bundle
        self._assert_bundle_rejected()

    def test_t13_bundle_with_only_crl(self):
        """CRL-only bundle loads in OpenSSL but holds no certificate."""
        ca_dir = self._tmp.name
        # Relative names and cwd keep path syntax out of the OpenSSL config.
        shutil.copy(self.cert, os.path.join(ca_dir, "ca.pem"))
        shutil.copy(self.key, os.path.join(ca_dir, "ca.key"))
        with open(os.path.join(ca_dir, "ca.cnf"), "w",
                  encoding="utf-8") as file:
            file.write(
                "[ca]\ndefault_ca=c\n[c]\n"
                "database=index.txt\ncrlnumber=crlnumber\n"
                "certificate=ca.pem\nprivate_key=ca.key\n"
                "default_md=sha256\ndefault_crl_days=1\n"
            )
        for name, content in (("index.txt", ""), ("crlnumber", "01\n")):
            with open(os.path.join(ca_dir, name), "w",
                      encoding="utf-8") as file:
                file.write(content)
        crl = os.path.join(ca_dir, "crl.pem")
        subprocess.run(
            ["openssl", "ca", "-gencrl", "-config", "ca.cnf",
             "-out", "crl.pem"],
            check=True, capture_output=True, cwd=ca_dir,
        )
        os.environ["AWS_CA_BUNDLE"] = crl
        self._assert_bundle_rejected()
