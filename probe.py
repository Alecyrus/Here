import asyncio
from util import Protocol
from util import setup_proxy
from util import Certificate

from async_timeout import timeout
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
import functools
import logging
import traceback
import certifi
import ssl
import logging
import aioredis

import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


async def cert_probe(host, certs, port=443, proxy=True):
    try:
        async with timeout(10) as cm: 
            loop = asyncio.get_event_loop()
            print(host,port)
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
            print(cert)
            certs.append("%s#%s" %(host, cert.get_certificate()))
    except Exception as e:
        traceback.print_exc()
        pass
    finally:
        if cm.expired:
            logging.exception("Timeout")

async def get_input():
    pool = await aioredis.create_pool('redis://172.29.152.196', maxsize=100)
    urls = await pool.execute('ZREVRANGEBYSCORE','alexa', 1000, 1, encoding="utf-8")
    return urls

try:
    certs = list()
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(asyncio.ensure_future(get_input()))
    print(result)
    tasks = [cert_probe(url, certs) for url in result]
    loop.run_until_complete(asyncio.gather(*tasks))
except KeyboardInterrupt as e:
    print(asyncio.Task.all_tasks())
    print(asyncio.gather(*asyncio.Task.all_tasks()).cancel())
    loop.stop()
    loop.run_forever()
finally:
    loop.close()
    print(certs)
    print(len(certs))
