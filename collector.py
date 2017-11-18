import asyncio
from util import Protocol
from util import Certificate
from util import saveRDN
from util import saveDomain
from util import saveCert
from util import setup_proxy
from sanic import Sanic
from sanic.response import json
import socks
from async_timeout import timeout
from motor.motor_asyncio import AsyncIOMotorClient

import logging

app = Sanic()
app.config.REQUEST_TIMEOUT = 60

async def do_connect(host, port, proxy=False):
   try:
       async with timeout(10) as cm: 
           try:
               loop = asyncio.get_event_loop()
               if proxy:
                   s_socket = await asyncio.ensure_future(setup_proxy(host, port))
                   (transport, protocol)  = await loop.create_connection(Protocol, server_hostname="", sock=s_socket, ssl=True)
               else:
                   (transport, protocol)  = await loop.create_connection(Protocol, host, port, ssl=True)
               der_string = (transport.get_extra_info("ssl_object").getpeercert(binary_form=True))
               transport.close()
               if proxy:
                   s_socket.close()
               cert = Certificate(der_string)
               save_tasks =[asyncio.ensure_future(saveCert(app.db, cert)),
                            asyncio.ensure_future(saveRDN(app.db, cert)), 
                            asyncio.ensure_future(saveDomain(app.db, cert))] 
                  
               results = await asyncio.gather(*save_tasks)
               for ret in results:
                   if not ret:
                       return False
               return True
           except Exception as e:
               print("Server(port:443) is not accessible")
               print(e)
               pass
       print(cm.expired)
   except Exception as e:
       print(e)
   finally:
       if cm.expired:
           print("Timeout")


@app.listener('before_server_start')
async def setup_db(app, loop):
    app.db = AsyncIOMotorClient().CertsDB

@app.listener('after_server_start')
async def notify_server_started(app, loop):
    print('Server successfully started!')

@app.listener('before_server_stop')
async def notify_server_stopping(app, loop):
    print('Server shutting down!')



@app.get("/v1/certificates")
async def test(request):
    try:
        params = request.args['target'][0]
        print("Starting to collect from %s" % params)
        flag = await do_connect(params, 443)
    except Exception as e:
        print(e)
        raise ServerError("Invlid request", status_code=500)
    if flag:
        resp = {"Info":"Collecting(%s) finished." %params}
    else:
        resp = {"Info":"Failed to collect(%s) the certificates." %params}
    print(resp)
    return json(resp)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8183, workers=5)

