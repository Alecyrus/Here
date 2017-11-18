import asyncio
import socks

import traceback
import arrow
from cryptography import x509

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding

class Protocol(asyncio.Protocol):
    def connection_made(self, transport):
        #print('Connection is created!')
        pass

    def data_received(self, data):
        #print('Data received: {!r}'.format(data.decode()))
        pass

    def connection_lost(self, exc):
        #print('The server closed the connection')
        pass


class Certificate(object):
    def __init__(self, der_string):
        self.cert_string = der_string
        self.cert = x509.load_der_x509_certificate(self.cert_string,default_backend())
        
    def b2s(self, b):
        return str(b, encoding = "utf-8")

    def prettytime(self, datetime):
        return arrow.get(datetime).format('YYYY-MM-DD HH:mm:ss ZZ')

    @property
    def version(self):
        return self.cert.version.name

    @property
    def fingerprint(self):
        return self.cert.fingerprint(hashes.SHA256())

    @property
    def serial_number(self):
        return hex(self.cert.serial_number)

    @property
    def public_key(self):
        return self.cert.public_key()

    @property
    def not_valid_before(self):
        return self.prettytime(self.cert.not_valid_before)

    @property
    def not_valid_after(self):
        return self.prettytime(self.cert.not_valid_after)

    @property
    def issuer(self):
        return self.cert.issuer

    @property
    def subject(self):
        return self.cert.subject

    @property
    def signature(self):
        return self.cert.signature

    @property
    def tbs_certificate_bytes(self):
        return self.cert.tbs_certificate_bytes

    @property
    def signature_hash_algorithm(self):
        return self.cert.signature_hash_algorithm

    @property
    def signature_hash_oid(self):
        return self.cert.signature_hash_algorithm_oid.name
 
    @property
    def extentions(self):
        extentions = list()
        for ext in self.cert.extentions:
            extention.append(ext.name)
        return extentions

    def get_certificate(self, encoding=Encoding.PEM):
        res = self.b2s(self.cert.public_bytes(encoding=encoding)).replace("\n", "")    
        return res 



    async def get_info(self):
        cinfo = dict()
        try:
            cinfo['version'] = self.version
            cinfo['serial_number'] = self.serial_number
            cinfo['pem'] = self.get_certificate()
            cinfo['der'] = self.cert_string
            cinfo['serial_number'] = self.serial_number
            cinfo['not_valid_before'] = self.not_valid_before
            cinfo['not_valid_after'] = self.not_valid_after
            #cinfo['issuer'] = self.issuer
            #cinfo['subject'] = self.subject
            cinfo['signature'] = self.signature
            cinfo['tbs_certificate_bytes'] = self.tbs_certificate_bytes
        except Exception as e:
            traceback.print_exc()
        return cinfo 

async def setup_proxy(host, port):
    s_socket = socks.socksocket()
    s_socket.set_proxy(socks.SOCKS5, "localhost")
    s_socket.setblocking(0)
    s_socket.connect((host, port))
    return s_socket

async def saveCert(db, cert):
    try:
        data = await cert.get_info()
        res = await db.Certificates.insert_one(data) 
        if res.acknowledged:
            return True
        else:
            return False
    except Exception as e:
        traceback.print_exc()
        return False
    

async def saveDomain(db, cert):
    return True

async def saveRDN(db, cert):
    return True


