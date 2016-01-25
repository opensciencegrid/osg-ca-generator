"""Create DigiCert-like OSG test CAs and certificates"""

import errno
import os
import pwd
import re
import socket
from subprocess import Popen, PIPE

class CA(object):
    """
    DigiCert-like certificate authorities (CAs) that can be used to generate
    host or user certificates.
    """
    _GRID_SEC_DIR = '/etc/grid-security/'
    _CERTS_DIR = os.path.join(_GRID_SEC_DIR, 'certificates')
    _CONFIG_PATH = '/etc/pki/tls/osg-test-ca.conf'
    _EXT_CONFIG_PATH = '/etc/pki/tls/osg-test-extensions.conf'
    _SERIAL_NUM = 'A1B2C3D4E5F6'

    def __init__(self, subject, days=10, force=False):
        """
        Create a CA (and crl) with the given subject.

        'days' specifies the number of days before the certificate expires
        'force' will overwrite any existing certs and keys if set to True
        """
        self.subject = subject
        try:
            basename = re.search(r'.*\/CN=([^\/]*)', subject).group(1).replace(' ', '-')
        except AttributeError:
            raise CertException('Could not find CN in subject')
        self._subject_base = re.sub(r'\/CN=.*', '', subject)

        self.path = os.path.join(self._CERTS_DIR, basename + '.pem')
        self.keypath = os.path.splitext(self.path)[0] + '.key'
        if os.path.exists(self.path) and not force:
            return

        # Place necessary config and folders for CA generation
        self._write_openssl_config()
        if not os.path.exists(self._CERTS_DIR):
            os.makedirs(self._CERTS_DIR, 0755)

        # Generate the CA
        _run_command(('openssl', 'genrsa', '-out', self.keypath, '2048'), 'generate CA private key')
        _run_command(('openssl', 'req', '-sha256', '-new', '-x509', '-out', self.path, '-key',
                      self.keypath, '-subj', subject, '-config', self._CONFIG_PATH, '-days', str(days)),
                     'generate CA')

        # Add supporting CA files
        self._ca_support_files()
        self.crl()

    @classmethod
    def load(cls, ca_path):
        """Load a CA from the location given by ca_path"""
        ca_subject, _ = certificate_info(ca_path)
        return cls(ca_subject)

    def hostcert(self, days=10, force=False):
        """
        Creates a host certificate (hostcert.pem) and host key (hostkey.pem)
        in /etc/grid-security from the given CA instance.

        'days' specifies the number of days before the certificate expires
        'force' will overwrite any existing certs and keys if set to True
        """
        host_path = os.path.join(self._GRID_SEC_DIR, 'hostcert.pem')
        if os.path.exists(host_path) and not force:
            return
        host_keypath = os.path.join(self._GRID_SEC_DIR, 'hostkey.pem')
        host_pk_der = "hostkey.der"

        host_subject = self._subject_base + '/OU=Services/CN=' + _get_hostname()
        host_request = "host_req"

        try:
            # Generate host key (in DER format)
            _run_command(('openssl', 'req', '-new', '-nodes', '-out', host_request, '-keyout', host_pk_der, '-subj',
                          host_subject), 'generate host cert request')
            # Run the private key through RSA to get proper format (-keyform doesn't work in openssl > 0.9.8)
            _run_command(('openssl', 'rsa', '-in', host_pk_der, '-outform', 'PEM', '-out', host_keypath),
                         'generate host private key')
            os.chmod(host_keypath, 0400)

            # Generate host cert
            _run_command(('openssl', 'ca', '-md', 'sha256', '-config', self._CONFIG_PATH, '-cert', self.path,
                          '-keyfile', self.keypath, '-days', str(days), '-policy', 'policy_anything', '-preserveDN',
                          '-extfile', self._EXT_CONFIG_PATH, '-in', host_request, '-notext', '-out', host_path,
                          '-outdir', '.', '-batch'),
                         'generate host cert')
        finally:
            # Cleanup
            os.remove(host_pk_der)
            os.remove(host_request)
            # os.remove(_SERIAL_NUM + ".pem")

    def usercert(self, username, password, days=10, force=False):
        """
        Creates a user cert (usercert.pem) and user key (userkey.pem)
        in ~username/.globus/ from the given CA instance.

        'password' specifies the password to use for the user's private key
        'days' specifies the number of days before the certificate expires
        'force' will overwrite any existing certs and keys if set to True
        """
        globus_dir = os.path.join(os.path.expanduser('~' + username), '.globus')
        user_path = os.path.join(globus_dir, 'usercert.pem')
        if os.path.exists(user_path) and not force:
            return
        user_keypath = os.path.join(globus_dir, 'userkey.pem')
        user_subject = self._subject_base + '/OU=People/CN=' + username
        user_request = 'user_req'

        if not os.path.exists(globus_dir):
            os.makedirs(globus_dir, 0755)

        # Generate user key
        _run_command(("openssl", "req", "-sha256", "-new", "-out", user_request, "-keyout", user_keypath, "-subj",
                      user_subject, '-passout', 'pass:' + password), 'generate user cert request and key')
        os.chmod(user_keypath, 0400)

        # Generate user cert
        _run_command(('openssl', 'ca', '-md', 'sha256', '-config', self._CONFIG_PATH, '-cert', self.path, '-keyfile',
                      self.keypath, '-days', str(days), '-policy', 'policy_anything', '-preserveDN', '-extfile',
                      self._EXT_CONFIG_PATH, '-in', user_request, '-notext', '-out', user_path, '-outdir', '.',
                      '-batch'), "generate user cert")

        user = pwd.getpwnam(username)
        for path in (user_path, user_keypath, globus_dir):
            os.chown(path, user.pw_uid, user.pw_gid)

    def crl(self, days=10):
        """
        Create CRL file for the CA instance

        'days' specifies the number of days before the certificate expires
        """
        crl_path = os.path.splitext(self.path)[0] + '.r0'
        command = ("openssl", "ca", "-gencrl", "-config", self._CONFIG_PATH, "-cert", self.path, "-keyfile",
                   self.keypath, "-crldays", str(days), "-out", crl_path)
        _run_command(command, "generate CRL")

    def _write_openssl_config(self):
        """Place the necessary openssl config required to mimic DigiCert"""
        openssl_dir = '/etc/pki/CA/'
        ext_contents = """authorityKeyIdentifier=keyid,issuer
    subjectKeyIdentifier=hash
    subjectAltName=DNS:%s
    keyUsage=critical,digitalSignature,keyEncipherment,dataEncipherment
    extendedKeyUsage=serverAuth,clientAuth
    certificatePolicies=1.2.840.113612.5.2.2.1,2.16.840.1.114412.31.1.1.1,1.2.840.113612.5.2.3.3.2
    basicConstraints=critical,CA:false""" % _get_hostname

        openssl_config = open('/etc/pki/tls/openssl.cnf', 'r')
        config_contents = openssl_config.read()
        openssl_config.close()
        replace_text = [("# crl_extensions	= crl_ext", "crl_extensions	= crl_ext"),
                        ("basicConstraints = CA:true", "basicConstraints = critical, CA:true"),
                        ("# keyUsage = cRLSign, keyCertSign",
                         "keyUsage = critical, digitalSignature, cRLSign, keyCertSign"),
                        ("dir		= ../../CA		# Where everything is kept",
                         "dir		= %s		# Where everything is kept" % openssl_dir)]
        for (old, new) in replace_text:
            config_contents = config_contents.replace(old, new)
        _write_file(self._CONFIG_PATH, config_contents)
        _write_file(self._EXT_CONFIG_PATH, ext_contents)
        _write_file(openssl_dir + "index.txt", "")
        _write_file(openssl_dir + "serial", self._SERIAL_NUM)
        _write_file(openssl_dir + "crlnumber", "01")

    def _ca_support_files(self):
        """Place the namespace, signing_policy, and hash symlinks required by the CA"""
        ca_name = os.path.splitext(os.path.basename(self.path))[0]

        # Grab hashes from CA
        _, ssl_hash, _ = _run_command(('openssl', 'x509', '-in', self.path, '-noout', '-subject_hash'),
                                      "Couldn't get old hash of test cert")
        hashes = [ssl_hash.strip()]

        # openssl-1.x has a -subject_hash_old flag that doesn't exist in openssl-0.x
        _, openssl_version, _ = _run_command(('openssl', 'version'),
                                             "Couldn't find openssl version")
        if re.match(r'OpenSSL\s+1.+', openssl_version):
            _, old_ssl_hash, _ = _run_command(('openssl', 'x509', '-in', self.path, '-noout', '-subject_hash_old'),
                                              "Couldn't get old hash of test cert")
            hashes.append(old_ssl_hash.strip())

        # Add signing policy and namespaces files
        namespace_content = """##############################################################################
    #NAMESPACES-VERSION: 1.0
    #
    # @(#)xyxyxyxy.namespaces
    # CA alias    : OSG-Test-CA
    #    subord_of: 
    #    subjectDN: /DC=org/DC=Open Science Grid/O=OSG Test/CN=OSG Test CA
    #    hash     : xyxyxyxy
    #
    TO Issuer "/DC=org/DC=Open Science Grid/O=OSG Test/CN=OSG Test CA" \
      PERMIT Subject "/DC=org/DC=Open Science Grid/.*"
    """.replace('xyxyxyxy', hashes[0])
        signing_content = """# OSG Test CA Signing Policy
    access_id_CA		X509	'%s'
    pos_rights		globus	CA:sign
    cond_subjects		globus	'"/DC=org/DC=Open Science Grid/*"'
    """ % self.subject

        _write_file(os.path.join(self._CERTS_DIR, ca_name + '.namespaces'),
                    namespace_content)
        _write_file(os.path.join(self._CERTS_DIR, ca_name + '.signing_policy'),
                    signing_content)

        # Create hash links
        links = [('.pem', '.0'),
                 ('.signing_policy', '.signing_policy'),
                 ('.namespaces', '.namespaces'),
                 ('.r0', '.r0')]
        for subject_hash in hashes:
            for source_ext, link_ext in links:
                try:
                    os.symlink(ca_name + source_ext,
                               os.path.join(self._CERTS_DIR, subject_hash + link_ext))
                except OSError, e: 
                    if e.errno == errno.EEXIST:
                        continue # safe to skip if symlink already exists

def certificate_info(path):
    """Extracts and returns the subject and issuer from an X.509 certificate."""
    command = ('openssl', 'x509', '-noout', '-subject', '-issuer', '-in', path)
    status, stdout, stderr = _run_command(command, 'Fetching certificate info')
    if (status != 0) or len(stdout.strip()) == 0 or len(stderr.strip()) != 0:
        raise CertException('Could not extract subject or issuer from %s' % path)
    subject_issuer_re = r'subject\s*=\s*([^\n]+)\nissuer\s*=\s*([^\n]+)\n'
    matches = re.match(subject_issuer_re, stdout).groups()
    if matches is None:
        raise OSError(status, stdout)
    subject, issuer = matches
    return (subject, issuer)

class CertException(Exception):
    """Exception class for certificate errors"""
    pass

def _run_command(cmd, msg):
    """Takes a shell command (formatted as a tuple) and runs it"""
    p = Popen(cmd, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    if p.returncode != 0:
        raise CertException("%s\nCOMMAND:\n%s\nSTDOUT:\n%s\nSTDERR:\n%s\n"
                            % (msg, ' '.join(cmd), stdout, stderr))
    return p.returncode, stdout, stderr

def _get_hostname():
    """
    Returns the hostname of the current system, returns None if it can't
    get the hostname. Stolen from osg-test
    """
    try:
        return socket.gethostbyaddr(socket.gethostname())[0]
    except socket.error:
        return None

def _write_file(path, contents):
    """Utility function for writing to a file"""
    f = open(path, 'w')
    f.write(contents)
    f.close()
