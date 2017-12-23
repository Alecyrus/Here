import asyncio
from util import Protocol
from util import Certificate
from util import setup_proxy

import socks
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

from sanic import Sanic
from sanic.response import json

app = Sanic()
app.config.REQUEST_TIMEOUT = 60


async def do_connect(host, port, proxy=True):
    try:
        async with timeout(20) as cm: 
            try:
                loop = asyncio.get_event_loop()
                context = ssl.SSLContext()
                context.verify_mode = ssl.CERT_NONE
                context.load_verify_locations(certifi.where())
                if proxy:
                    s_socket = await asyncio.ensure_future(setup_proxy(host, port))
                    (transport, protocol)  = await loop.create_connection(Protocol, server_hostname="", sock=s_socket, ssl=context)
                else:
                    (transport, protocol)  = await loop.create_connection(Protocol, host, port, server_hostname="", ssl=context)
                der_string = transport.get_extra_info("ssl_object").getpeercert(binary_form=True)
                transport.close()
                cert = Certificate().init_cert(der_string=der_string)
                conn = await aioredis.create_connection(
                'redis://172.29.152.196/0')
                print(cert)
                await conn.execute('hmset', host, "cert", der_string)
                conn.close()
                await conn.wait_closed()
            except Exception as e:
                traceback.print_exc()
                raise
    except Exception as e:
        traceback.print_exc()
        pass
    finally:
        if cm.expired:
            logging.exception("Timeout")

#async def main():
#    try:
        #pool = await aioredis.create_pool('redis://172.29.152.196', maxsize=100)
        #urls = await pool.execute('ZREVRANGEBYSCORE','alexa', 10000, 1, encoding="utf-8")


@app.listener('before_server_start')
async def setup_db(app, loop):
    app.DBPool = await aioredis.create_pool('redis://172.29.152.196', maxsize=500)
    app.executor = ThreadPoolExecutor()



def sub_loop(host, port, Pool):
    flag = True
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(do_connect(host, port))
    except Exception as e:
        traceback.print_exc()
        flag =  False
    finally:
        if loop.is_running():
            loop.close()
        return flag


@app.get("/v1/certificates")        
async def main(request):
    try:
        params = request.args['target'][0]
        flag = True
        flag = await asyncio.get_event_loop().run_in_executor(app.executor, functools.partial(sub_loop, params, 443, app.DBPool))
    except Exception as e:
        traceback.print_exc()
        flag = False
        pass
    if flag:
        resp = {"Info":"Collecting(%s) finished." %params}
    else:
        resp = {"Info":"Failed to collect(%s) the certificates." %params}
    print(resp)
    return json(resp)



app.run(host="0.0.0.0", port=8183, workers=5)
