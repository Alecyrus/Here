import asyncio
import socks
import arrow
import copy
import aiosocks
import pymongo
import aiohttp
import asyncio
import riprova
import hashlib
import functools
import pymongo
import traceback
import cryptography

from riprova import retry
from cryptography import x509
from pymongo import ReturnDocument
from aiosocks.connector import ProxyConnector, ProxyClientRequest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding

MAX_AUTO_RECONNECT_ATTEMPTS = 4

def graceful_auto_reconnect(mongo_op_func):
    """Gracefully handle a reconnection event."""
    @functools.wraps(mongo_op_func)
    def wrapper(*args, **kwargs):
        for attempt in range(MAX_AUTO_RECONNECT_ATTEMPTS):
            try:
                return mongo_op_func(*args, **kwargs)
            except Exception as e:
                wait_t = 0.5 * pow(2, attempt) # exponential back off
                print("PyMongo auto-reconnecting... %s. Waiting %.1f seconds.", str(e), wait_t)
                asyncio.sleep(wait_t)
  
    return wrapper



@ graceful_auto_reconnect
async def db_operator(func):
    return await func



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
        print(str(e))
        #traceback.print_exc()
        return content


async def get_upper_certificate_crt(url):
    conn =  ProxyConnector(remote_resolve=True)
    async with aiohttp.ClientSession(connector=conn, request_class=ProxyClientRequest) as session:
        cert = False
        try:
            cert = await fetch(session, url)
        except Exception as e:
            print(str(e))
            #traceback.print_exc()
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
        extensions = dict()
        for ext in self.cert.extensions:
            extensions[ext.oid._name] = str(ext.value)
        return extensions



    @property
    def basicConstraints(self):
        ext = dict()
        try:
            temp = self.cert.extensions.get_extension_for_class(x509.BasicConstraints)
            ext['critical'] = temp.critical
            ext['ca'] = temp.value._ca
            ext['path_length'] = temp.value._path_length
        except Exception as e:
            pass
        finally:
            return ext
            
    @property
    def authorityInformationAccess(self):
        ext = dict()
        try:
            temp = self.cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            ext['critical'] = temp.critical
            for ainfo in temp.value:
                ext[ainfo.access_method._name] = ainfo.access_location.value
        except Exception as e:
            pass
        finally:
            return ext

    @property
    def subjectAlternativeName(self):
        ext = dict()
        try:
            temp = self.cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            ext['critical'] = temp.critical
            ext['DNSName'] = temp.value.get_values_for_type(x509.DNSName)
            ext['RFC822Name'] = temp.value.get_values_for_type(x509.RFC822Name)
            ext['DirectoryName'] = list()
            for dn in temp.value.get_values_for_type(x509.DirectoryName):
                 for name in dn:
                     ext['DirectoryName'].append(name.value)
            ext['UniformResourceIdentifier'] = temp.value.get_values_for_type(x509.UniformResourceIdentifier)
            ext['IPAddress'] = temp.value.get_values_for_type(x509.IPAddress)
            ext['RegisteredID'] = temp.value.get_values_for_type(x509.RegisteredID)
            ext['OtherName'] = temp.value.get_values_for_type(x509.OtherName)
        except Exception as e:
            pass
        finally:
            return ext

    @property
    def keyUsage(self):
        ext = dict()
        try:
            temp = self.cert.extensions.get_extension_for_class(x509.KeyUsage)
            ext['critical'] = temp.critical
            ext['tal_signature'] = temp.value.digital_signature
            ext['content_commitment'] = temp.value.content_commitment
            ext['key_encipherment'] = temp.value.key_encipherment
            ext['data_encipherment'] = temp.value.data_encipherment
            ext['key_agreement'] = temp.value.key_agreement
            if temp.value.key_agreement:
                ext['encipher_only'] = temp.value.encipher_only
                ext['decipher_only'] = temp.value.decipher_only
            ext['key_cert_sign'] = temp.value.key_cert_sign
            ext['crl_sign'] = temp.value.crl_sign
        except Exception as e:
            pass
        finally:
            return ext





    @property
    def crlDistributionPoints(self):
        ext = dict()
        try:
            temp = self.cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            for ainfo in temp.value:
                t = list()
                for value in ainfo.full_name:
                    t.append(value.value) 
                ext["full_name"] = t
                ext["relative_name"] = ainfo.relative_name
                ext["reasons"] = ainfo.reasons
                ext["crl_issuer"] = ainfo.crl_issuer
        except Exception as e:
            pass
        finally:
            return ext


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
                    return ainfo.access_location.value
            if not upper:
                raise  AttributeError("No caIssuers")
        except Exception as e:
            filters = self.get_issuer_info()
            filters.pop("trusted")
            check = await db_operator(db.RDNs.find_one(filters))
            if check:
                root_cert = await db_operator(db.Certificates.find_one({"subject":check['upper']}))
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
            identity = hashlib.sha1(str(rdn).encode("utf-8")).hexdigest()
            rdn['digest'] = identity
            rdn["trusted"] = self.trusted
                
        except Exception as e:
            #traceback.print_exc()
            print(str(e))
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
            cinfo['fingerprint'] = self.fingerprint
            cinfo['trusted'] = self.trusted
            cinfo['root'] = root
            cinfo['BasicConstraints'] = self.basicConstraints
            cinfo['AuthorityInformationAccess'] = self.authorityInformationAccess
            cinfo['CRLDistributionPoints'] = self.crlDistributionPoints
            cinfo['SubjectAlternativeName'] = self.subjectAlternativeName
            cinfo['KeyUsage'] = self.keyUsage
            cinfo['not_valid_before'] = self.not_valid_before
            cinfo['not_valid_after'] = self.not_valid_after
            cinfo['signature'] = self.signature
            cinfo['tbs_certificate_bytes'] = self.tbs_certificate_bytes
        except Exception as e:
            #traceback.print_exc()
            print(str(e))
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
        check = await db_operator(db.Certificates.find_one(data))
        if check:
            return check['_id']
        res = await db_operator(db.Certificates.insert_one(data))
        if res.acknowledged:
            return res.inserted_id
        else:
            print("Error: Failed")
            return False
    except Exception as e:
        print(str(e))
        #traceback.print_exc()
        return False
    

async def saveDomain(db, host, cert_id):
    try:
        check = await db_operator(db.Domains.find_one({"host":host}))
        if check:
            if check['cert'] != cert_id and ( not check['cert'] and cert_id ):
                await db_operator(db.Domains.find_one_and_update({"host":host},
                                                     {"$set":{"cert":cert_id}},
                                                      upsert=True,
                                                      return_document=ReturnDocument.AFTER))
            else:
                return True
        else:
            await db_operator(db.Domains.insert_one({"host":host,"cert":cert_id}))
    except Exception as e:
        print(str(e))
        #traceback.print_exc()
        return False
    return True

async def _saveRDN(db, data, upper=None):
    try:
        update = copy.deepcopy(data) 
        update['upper'] = upper
        data.pop("trusted")
        check = await db_operator(db.RDNs.find_one(data))
        if check:
            if upper and not check['upper']:
                await db_operator(db.RDNs.update_one(data, {"$set":{"upper":upper}}))
            return check['_id']
        else:
            res = await db_operator(db.RDNs.insert_one(update))
        if res:
            return res.inserted_id
        else:
            return -1
    except Exception as e:
        print(str(e))
        traceback.print_exc()
        raise

async def saveRDNs(db, cert, upper=None):
    try:
        res1 = await  _saveRDN(db, cert.get_issuer_info(), upper=upper)
        res2 = await  _saveRDN(db, cert.get_subject_info(), upper=res1)
        return res1, res2
    except Exception as e:
        print(str(e))
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
            print(str(e))
            traceback.print_exc()
            raise
    return chain
