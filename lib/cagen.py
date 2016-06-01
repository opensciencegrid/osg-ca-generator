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

    Pre-existing CAs can be loaded via the subject name and __init__()
    (without the force option) or by its path with load().
    """
    _GRID_SEC_DIR = '/etc/grid-security/'
    _CERTS_DIR = os.path.join(_GRID_SEC_DIR, 'certificates')
    _CONFIG_PATH = '/etc/pki/tls/osg-test-ca.conf'
    _EXT_CONFIG_PATH = '/etc/pki/tls/osg-test-extensions.conf'
    _SERIAL_NUM = 'A1B2C3D4E5F6'

    def __init__(self, subject, days=10, force=False, mimic='digicert'):
        """
        Create a CA (and crl) with the given subject.

        days - specifies the number of days before the certificate expires
        force - will overwrite any existing certs and keys if set to True
        mimic - type of CA/certs to mimic: 'cilogon' or 'digicert' (default)
        """
        self.subject = subject
        self.mimic = mimic
        self.created = False
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
        try:
            os.makedirs(os.path.join(self._CERTS_DIR, 'newcerts'), 0755)
        except OSError, e:
            if e.errno == errno.EEXIST:
                pass

        # Generate the CA
        _run_command(('openssl', 'genrsa', '-out', self.keypath, '2048'), 'generate CA private key')
        _run_command(('openssl', 'req', '-sha256', '-new', '-x509', '-out', self.path, '-key',
                      self.keypath, '-subj', subject, '-config', self._CONFIG_PATH, '-days', str(days)),
                     'generate CA')

        # Add supporting CA files
        self._ca_support_files()
        self.crl()
        self.created = True

    @classmethod
    def load(cls, ca_path):
        """Load a CA from the location given by ca_path"""
        ca_subject, _ = certificate_info(ca_path)
        return cls(ca_subject)

    def hostcert(self, days=10):
        """
        Creates a host certificate (hostcert.pem) and host key (hostkey.pem)
        in /etc/grid-security from the given CA instance.

        days - specifies the number of days before the certificate expires

        Returns strings:
        Host certificate subject, host certificate path, host certificate key path
        """
        host_path = os.path.join(self._GRID_SEC_DIR, 'hostcert.pem')
        host_keypath = os.path.join(self._GRID_SEC_DIR, 'hostkey.pem')
        host_pk_der = "hostkey.der"

        host_subject = self._subject_base + '/OU=Services/CN=' + _get_hostname()
        host_request = "host_req"

        # Generate host request and key (in DER format)
        _run_command(('openssl', 'req', '-new', '-nodes', '-out', host_request, '-keyout', host_pk_der, '-subj',
                      host_subject), 'generate host cert request')
        try:
            # Run the private key through RSA to get proper format (-keyform doesn't work in openssl > 0.9.8)
            _run_command(('openssl', 'rsa', '-in', host_pk_der, '-outform', 'PEM', '-out', host_keypath),
                         'generate host private key')
            os.chmod(host_keypath, 0400)

            # Generate host cert
            _run_command(('openssl', 'ca', '-md', 'sha256', '-config', self._CONFIG_PATH, '-cert', self.path,
                          '-keyfile', self.keypath, '-days', str(days), '-policy', 'policy_anything',
                          '-preserveDN', '-extfile', self._EXT_CONFIG_PATH, '-in', host_request, '-notext', '-out',
                          host_path, '-batch'),
                         'generate host cert')
        finally:
            os.remove(host_pk_der)
            os.remove(host_request)
        return host_subject, host_path, host_keypath

    def usercert(self, username, password, days=10):
        """
        Creates a user cert (usercert.pem) and user key (userkey.pem)
        in ~username/.globus/ from the given CA instance.

        days - specifies the number of days before the certificate expires

        Returns strings:
        User certificate subject, user certificate path, user certificate key path
        """
        globus_dir = os.path.join(os.path.expanduser('~' + username), '.globus')
        user_path = os.path.join(globus_dir, 'usercert.pem')
        user_keypath = os.path.join(globus_dir, 'userkey.pem')
        user_subject = self._subject_base + '/OU=People/CN=' + username
        user_request = 'user_req'

        try:
            os.makedirs(globus_dir, 0755)
        except OSError, e:
            if e.errno == errno.EEXIST:
                pass

        # Generate user request and key
        _run_command(("openssl", "req", "-sha256", "-new", "-out", user_request, "-keyout", user_keypath, "-subj",
                      user_subject, '-passout', 'pass:' + password), 'generate user cert request and key')
        os.chmod(user_keypath, 0400)

        try:
            # Generate user cert
            _run_command(('openssl', 'ca', '-md', 'sha256', '-config', self._CONFIG_PATH, '-cert', self.path,
                          '-keyfile', self.keypath, '-days', str(days), '-policy', 'policy_anything',
                          '-preserveDN', '-extfile', self._EXT_CONFIG_PATH, '-in', user_request, '-notext', '-out',
                          user_path, '-batch'), "generate user cert")

            user = pwd.getpwnam(username)
            for path in (user_path, user_keypath, globus_dir):
                os.chown(path, user.pw_uid, user.pw_gid)
        finally:
            os.remove(user_request)
        return user_subject, user_path, user_keypath

    def crl(self, days=10):
        """
        Create CRL file for the CA instance

        days - specifies the number of days before the certificate expires
        """
        crl_path = os.path.splitext(self.path)[0] + '.r0'
        command = ("openssl", "ca", "-gencrl", "-config", self._CONFIG_PATH, "-cert", self.path, "-keyfile",
                   self.keypath, "-crldays", str(days), "-out", crl_path)
        _run_command(command, "generate CRL")
        return crl_path

    #TODO: Implement cleanup function

    def _write_openssl_config(self):
        """Place the necessary openssl config required to mimic DigiCert"""
        if self.mimic == 'cilogon':
            ext_key_usage = 'critical, cRLSign, keyCertSign'
            cert_policies = '1.3.6.1.4.1.34998.1.6'
            key_id = ''
            pathlen = ''
        else:
            ext_key_usage = 'critical, digitalSignature, cRLSign, keyCertSign'
            cert_policies = '1.2.840.113612.5.2.2.1, 2.16.840.1.114412.31.1.1.1, 1.2.840.113612.5.2.3.3.2'
            key_id = "authorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n"
            pathlen = ', pathlen:0'

        openssl_dir = '/etc/pki/CA/' # TODO: This may need to be unique for each CA
        ext_contents = """%ssubjectAltName=DNS:%s
keyUsage=critical,digitalSignature,keyEncipherment,dataEncipherment
extendedKeyUsage=serverAuth,clientAuth
certificatePolicies=%s
basicConstraints=critical,CA:false
""" % (key_id, _get_hostname(), cert_policies)

        openssl_config = open('/etc/pki/tls/openssl.cnf', 'r')
        config_contents = openssl_config.read()
        openssl_config.close()
        replace_text = [("# crl_extensions	= crl_ext", "crl_extensions	= crl_ext"),
                        ("basicConstraints = CA:true", "basicConstraints = critical, CA:true%s" % pathlen),
                        ("# keyUsage = cRLSign, keyCertSign",
                         "keyUsage = %s" % ext_key_usage),
                        ("dir		= ../../CA		# Where everything is kept",
                         "dir		= %s		# Where everything is kept" % openssl_dir)]
        for (old, new) in replace_text:
            config_contents = config_contents.replace(old, new)

        _write_file(self._CONFIG_PATH, config_contents)
        _write_file(self._EXT_CONFIG_PATH, ext_contents)
        _write_file(openssl_dir + "index.txt", "")
        _write_file(openssl_dir + "index.txt.attr", "unique_subject = no\n") # TODO: Implement cert revocation instead
        _write_file(openssl_dir + "serial", self._SERIAL_NUM)
        _write_file(openssl_dir + "crlnumber", "01\n")

        # openssl 0.x doesn't create this for us
        try:
            os.makedirs(os.path.join(openssl_dir, 'newcerts'), 0755)
        except OSError, e:
            if e.errno == errno.EEXIST:
                pass

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
    #    subjectDN: %s
    #    hash     : %s
    #
    TO Issuer "%s" \
      PERMIT Subject "%s/.*"
    """ % (self.subject, hashes[0], self.subject, self._subject_base)
        signing_content = """# OSG Test CA Signing Policy
    access_id_CA		X509	'%s'
    pos_rights		globus	CA:sign
    cond_subjects		globus	'"%s/*"'
    """ % (self.subject, self._subject_base)

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
