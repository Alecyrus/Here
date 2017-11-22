import asyncio
from util import Protocol
from util import Certificate
from util import saveRDNs
from util import saveDomain
from util import saveCert
from util import setup_proxy
from util import get_certificate_chain
from sanic import Sanic
from sanic.response import json
import socks
from async_timeout import timeout
from motor.motor_asyncio import AsyncIOMotorClient
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import functools
import logging
import traceback
import certifi
import ssl


app = Sanic()
app.config.REQUEST_TIMEOUT = 60

async def do_connect(host, port, db, proxy=True):
   try:
       async with timeout(60) as cm: 
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
               chain = await get_certificate_chain(db, cert)
               if not chain:
                   await saveDomain(db, host, False)
                   raise AttributeError("Time out")
               cert_id = None
               upper = None
               for i in range(len(chain)-1, -1, -1):
                   issuer, subject = await saveRDNs(db, chain[i])
                   root = False
                   if i == len(chain)-1:
                       root = True
                   upper = await saveCert(db, chain[i], issuer['_id'], subject['_id'], root=root, upper=upper)
                   if i == 0:
                       cert_id = upper
               await saveDomain(db, host, cert_id)
           except Exception as e:
               raise
   except Exception as e:
       await saveDomain(db, host, None)
       raise
   finally:
       if cm.expired:
           print("Timeout")


@app.listener('before_server_start')
async def setup_db(app, loop):
    app.executor = ThreadPoolExecutor()
    db = AsyncIOMotorClient(host='172.29.152.161', port=20000).CertsDB
    context = ssl.SSLContext()
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(certifi.where())
    root_cas = context.get_ca_certs(binary_form=True)
    for root_ca in root_cas:
        issuer, subject = await saveRDNs(db, Certificate(trusted=True).init_cert(der_string=root_ca)) 
        await saveCert(db, Certificate(trusted=True).init_cert(der_string=root_ca), issuer['_id'], subject['_id'], root=True, upper=None)


@app.listener('after_server_start')
async def notify_server_started(app, loop):
    print('Server successfully started!')

@app.listener('before_server_stop')
async def notify_server_stopping(app, loop):
    print('Server shutting down!')

    

def sub_loop(host, port):
    flag = True
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        db = AsyncIOMotorClient(host='172.29.152.161', port=20000).CertsDB
        loop.run_until_complete(do_connect(host, port, db))
    except Exception as e:
        flag =  False
        traceback.print_exc()
    finally:
        if loop.is_running():
            loop.close()
        return flag
        

@app.get("/v1/certificates")
async def test(request):
    try:
        params = request.args['target'][0]
        print("Starting to collect from %s" % params)
        #flag = await do_connect(params, 443)
        flag = await asyncio.get_event_loop().run_in_executor(app.executor, functools.partial(sub_loop, params, 443))
    except Exception as e:
        traceback.print_exc()
        raise ServerError("Invlid request", status_code=500)
    if flag:
        resp = {"Info":"Collecting(%s) finished." %params}
    else:
        resp = {"Info":"Failed to collect(%s) the certificates." %params}
    print(resp)
    return json(resp)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8183, workers=1)

