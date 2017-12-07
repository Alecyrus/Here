import asyncio
from util import Protocol
from util import Certificate
from util import saveRDNs
from util import saveDomain
from util import saveCert
from util import setup_proxy
from util import get_certificate_chain

import socks
from async_timeout import timeout
from motor.motor_asyncio import AsyncIOMotorClient
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import functools
import logging
import traceback
import certifi
import ssl
import logging


async def do_connect(host, port, db, proxy=True):
   try:
       async with timeout(20) as cm: 
           try:
               loop = asyncio.get_event_loop()
               context = ssl.SSLContext()
               context.verify_mode = ssl.CERT_REQUIRED
               context.load_verify_locations(certifi.where())
               if proxy:
                   s_socket = await asyncio.ensure_future(setup_proxy(host, port))
                   (transport, protocol)  = await loop.create_connection(Protocol, server_hostname=host, sock=s_socket, ssl=context)
               else:
                   (transport, protocol)  = await loop.create_connection(Protocol, host, port, ssl=context)
               der_string = transport.get_extra_info("ssl_object").getpeercert(binary_form=True)
               transport.close()
               cert = Certificate().init_cert(der_string=der_string)

           except Exception as e:
               traceback.print_exc()
               print(e)
               raise
   except Exception as e:
       await saveDomain(db, host, None)
       raise
   finally:
       if cm.expired:
           logging.exception("Timeout")



def sub_loop(host, port):
    flag = True
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        conn = AsyncIOMotorClient(host='172.29.152.161',port=20000,connectTimeoutMS=1000, maxPoolSize=2000,socketKeepAlive=True)
        db = conn.CertsDB
        loop.run_until_complete(do_connect(host, port, db))
    except Exception as e:
        traceback.print_exc()
        flag =  False
        saveDomain(db, host, False)
    finally:
        if loop.is_running():
            loop.close()
        conn.close()
        return flag
        


async def test(target):
    try:
        flag = await asyncio.get_event_loop().run_in_executor(ThreadPoolExecutor(), functools.partial(sub_loop, target, 443))
    except Exception as e:
        traceback.print_exc()
        flag = False
        pass
    if flag:
        resp = {"Info":"Collecting(%s) finished." %target}
    else:
        resp = {"Info":"Failed to collect(%s) the certificates." %target}
    print(resp)
    return resp


loop = asyncio.get_event_loop()
loop.run_until_complete(test("www.baidu.com"))
loop.close()