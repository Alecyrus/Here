import asyncio
import socks

import traceback
import arrow
from cryptography import x509
import cryptography
import copy

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from pymongo import ReturnDocument
import aiosocks
from aiosocks.connector import ProxyConnector, ProxyClientRequest
import pymongo

import aiohttp
import asyncio
from riprova import retry
import riprova


async def on_retry(err, next_try):
    print('Operation error: {}'.format(err))
    print('Next try in {}ms'.format(next_try))


@retry(on_retry=on_retry, backoff=riprova.ConstantBackoff(retries=10))
async def fetch(session, url):
    auth5 = aiosocks.Socks5Auth('proxyuser1', password='pwd')
    content = False
    try:
        async with session.get(url, proxy='socks5://127.0.0.1:1080',proxy_auth=auth5) as response:
            content = await response.read()
            return content
    except Exception as e:
        traceback.print_exc()
        return content


async def get_upper_certificate_crt(url):
    conn =  ProxyConnector(remote_resolve=True)
    async with aiohttp.ClientSession(connector=conn, request_class=ProxyClientRequest) as session:
        cert = False
        try:
            cert = await fetch(session, url)
        except Exception as e:
            traceback.print_exc()
        finally:
            return cert


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
    def __init__(self, trusted=None):
        self.setTrusted(trusted)
        
    def init_cert(self, der_string=None, pem_string=None):
        if der_string:
            self.der_string = der_string
            try:
                self.cert = x509.load_der_x509_certificate(der_string,default_backend())
            except ValueError as e:
                self.cert = x509.load_pem_x509_certificate(der_string,default_backend())
                pass
        if pem_string:
            self.pem_string = pem_string
            try:
                self.cert = x509.load_pem_x509_certificate(pem_string,default_backend())
            except ValueError as e:
                self.cert = x509.load_der_x509_certificate(pem_string,default_backend())
                pass
        return self

    def setTrusted(self, value):
        self.trusted = value

    def b2s(self, b):
        return str(b, encoding = "utf-8")

    def prettytime(self, datetime):
        return arrow.get(datetime).format('YYYY-MM-DD HH:mm:ss ZZ')

    def getTrusted(self):
        return self.trusted

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
        return self.cert.public_key(cryptography.hazmat.primitives.serialization.Encoding.PEM, \
 cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo)

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
    def extensions(self):
        extensions = list()
        for ext in self.cert.extensions:
            print(ext.oid._name)
            #extensions.append(ext.name)
        return extensions

    def get_certificate(self, encoding=Encoding.PEM):
        #res = self.b2s(self.cert.public_bytes(encoding=encoding)).replace("\n", "")    
        res = self.cert.public_bytes(encoding=encoding)   
        return res 

    async def get_upper_url(self, db):
        try:
            upper = None
            ainfos = self.cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            for ainfo in ainfos.value:
                if ainfo.access_method._name == "caIssuers":
                    print("ainfo.access_location.value",ainfo.access_location.value)
                    return ainfo.access_location.value
            if not upper:
                raise  AttributeError("No caIssuers")
        except Exception as e:
            filters = self.get_issuer_info()
            filters.pop("trusted")
            check = await db.RDNs.find_one(filters)
            if check:
                root_cert = await db.Certificates.find_one({"subject":check['upper']})
                if not root_cert:
                    return False
                return root_cert
            else:
                root = True
            return False

        

    def _rdn(self, _type):
        rdn = dict()
        try:
            rdns = eval("self.cert.%s" %_type)
            for r in rdns:
                rdn[r.oid._name] = r.value
            rdn["trusted"] = self.trusted
                
        except Exception as e:
            traceback.print_exc()
        finally:
            return rdn



    def get_issuer_info(self):
        return self._rdn("issuer")

    def get_subject_info(self):
        return self._rdn("subject")


    async def get_cert_info(self, root):
        cinfo = dict()
        try:
            cinfo['version'] = self.version
            cinfo['serial_number'] = self.serial_number
            cinfo['pem'] = self.get_certificate()
            cinfo['der'] = self.get_certificate(encoding=Encoding.DER)
            cinfo['serial_number'] = self.serial_number
            cinfo['fingerprint'] = self.fingerprint
            cinfo['trusted'] = self.trusted
            cinfo['root'] = root
            cinfo['not_valid_before'] = self.not_valid_before
            cinfo['not_valid_after'] = self.not_valid_after
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

async def saveCert(db, cert, issuer_id=None, subject_id=None, root=False, upper=None):
    try:
        data = await cert.get_cert_info(root=root)
        data['issuer'] = issuer_id
        data['subject'] = subject_id
        data['upper'] = upper
        check = await db.Certificates.find_one(data)
        if check:
            return check['_id']
        res = await db.Certificates.insert_one(data)
        if res.acknowledged:
            return res.inserted_id
        else:
            print("Error: Failed")
            return False
    except Exception as e:
        traceback.print_exc()
        return False
    

async def saveDomain(db, host, cert_id):
    try:
        check = await db.Domains.find_one({"host":host})
        if check:
            if check['cert'] != cert_id and ( not check['cert'] and cert_id ):
                await db.Domains.find_one_and_update({"host":host},
                                                     {"$set":{"cert":cert_id}},
                                                      upsert=True,
                                                      return_document=ReturnDocument.AFTER)
            else:
                return True
        else:
            await db.Domains.insert_one({"host":host,"cert":cert_id})
    except Exception as e:
        traceback.print_exc()
        return False
    return True

async def _saveRDN(db, data, upper=None):
    try:
        update = copy.deepcopy(data) 
        update['upper'] = upper
        res = await db.RDNs.find_one_and_update(data, 
                                                {"$set":{"upper":upper}},
                                                upsert=True,
                                                return_document=ReturnDocument.AFTER)
        if res:
            return res
        else:
            return False
    except Exception as e:
        raise

async def saveRDNs(db, cert):
    try:
        res1 = await  _saveRDN(db, cert.get_issuer_info())
        res2 = await  _saveRDN(db, cert.get_subject_info(), upper=res1['_id'])
        return res1, res2
    except Exception as e:
        traceback.print_exc()
        return False

async def get_certificate_chain(db, cert):
    chain=[cert]
    current = cert
    while True:
        try:
            upper_url = await current.get_upper_url(db)
            if isinstance(upper_url, dict):
                current = Certificate(trusted=True).init_cert(pem_string=upper_url['pem'])
                chain.append(current)
                break
            else:
                if upper_url is False:
                    chain[len(chain)-1].setTrusted(False)
                    break
                upper_crt = await get_upper_certificate_crt(upper_url)
                if not upper_crt:
                    return False
                current = Certificate().init_cert(der_string=upper_crt)
            chain.append(current)
        except Exception as e:
            traceback.print_exc()
            raise
    return chain
