"""Local-only UI fixture. Never imported by production entry points."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys
import threading
from urllib.parse import urlsplit

from flask import redirect, request, session
from werkzeug.serving import make_server
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import recursor_config


def main():
    with tempfile.TemporaryDirectory(prefix='pdnsadmin-ui-') as directory:
        root = Path(directory)
        ini = root / 'config.ini'
        ini.write_text(f'[flask]\nsecret_key=local-test\nsession_secure=False\nsession_file_dir={root}/sessions\n'
                       f'trust_proxy=False\n[oidc]\nenabled=False\n[pdns]\nurl_internal=http://pdns.invalid/api/v1/servers/internal\nurl_external=http://pdns.invalid/api/v1/servers/external\nkey_internal=test-only\nkey_external=test-only\n[recursor]\nsteven_url=\nstate_dir={root}/filters\ntargets=recursor1,recursor2,recursor3,recursor4\n' +
                       ''.join(f'[recursor:recursor{i}]\nhost=192.0.2.{i}\n' for i in range(1,5)))
        os.environ['DNSADMIN_CONFIG'] = str(ini)
        spec = importlib.util.spec_from_file_location('local_test_app', ROOT / 'pdnsadmin-z.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        module.logger.disabled = True
        zone = dict(id='example.org.', name='example.org.', kind='Native', serial=1, rrsets=[
            dict(name='example.org.', type='SOA', ttl=300, records=[dict(content='ns.example.org. hostmaster.example.org. 1 3600 600 86400 300', disabled=False)]),
            dict(name='example.org.', type='NS', ttl=300, records=[dict(content='ns.example.org.', disabled=False)]),
            dict(name='www.example.org.', type='A', ttl=300, records=[dict(content='192.0.2.1', disabled=False),dict(content='192.0.2.2', disabled=True)]),
            dict(name='_service._tcp.example.org.', type='SRV', ttl=300, records=[dict(content='10 5 443 www.example.org.', disabled=False)]),
            dict(name='example.org.', type='DNSKEY', ttl=300, records=[dict(content='257 3 13 ABCD', disabled=False)]),
        ])
        zones = {'internal': {'example.org.': copy.deepcopy(zone)}, 'external': {'example.org.': copy.deepcopy(zone)}}
        calls=[]
        release_deploy = threading.Event()
        def fake_deploy(target, payload, kind):
            release_deploy.wait(10)
            calls.append(['DEPLOY', target.name, [kind, payload]])
            return target.name != 'recursor2', 'Resultado local simulado.'
        recursor_config.deploy_operation = fake_deploy
        class FakeLaunch:
            def poll(self): return None
        def launch(args, **kwargs):
            threading.Thread(target=lambda: module.filter_store.run_job(args[-2]), daemon=True).start()
            return FakeLaunch()
        recursor_config.subprocess.Popen = launch
        def api(method, url, **kwargs):
            calls.append([method,url,kwargs.get('json')])
            parts=urlsplit(url).path.split('/')
            server='external' if 'external' in parts else 'internal'
            response=requests.Response()
            response.status_code=200
            if 'search-data' in parts:
                result=[dict(object_type='record',zone='example.org.',zone_id='example.org.',name='www.example.org.',type='A',ttl=300,content='192.0.2.1')]
            elif parts[-1]=='zones':
                if method=='POST':
                    data=kwargs['json']; name=data['name']
                    zones[server][name]=dict(id=name,name=name,kind=data['kind'],serial=1,rrsets=[])
                    result={};response.status_code=201
                else:result=list(zones[server].values())
            elif parts[-2]=='zones':
                name=parts[-1]
                if name not in zones[server]: response.status_code=404;result={'error':'Zona inexistente'}
                elif method=='DELETE': del zones[server][name];response.status_code=204;result={}
                elif method=='PATCH':
                    for rr in kwargs['json']['rrsets']:
                        existing=zones[server][name]['rrsets']
                        existing[:]=[row for row in existing if (row['name'],row['type'])!=(rr['name'],rr['type'])]
                        if rr['changetype']=='REPLACE':existing.append({key:value for key,value in rr.items() if key!='changetype'})
                    response.status_code=204;result={}
                else:result=zones[server][name]
            else:raise AssertionError('Unexpected API request: '+url)
            response._content=json.dumps(result).encode()
            return response
        for method in ('get','post','patch','delete'):
            setattr(module.requests, method, lambda url,_method=method,**kwargs:api(_method.upper(),url,**kwargs))

        @module.app.get('/_test/login')
        def test_login():
            session.clear()
            session.update(user='local-test', role=request.args.get('role','admin'),admin_mode='seguro',pdns_server='internal',pending_changes=[])
            return redirect('/?server=internal')

        @module.app.get('/_test/release-deploy')
        def test_release_deploy():
            release_deploy.set()
            return {'released': True}

        @module.app.get('/_test/calls')
        def test_calls():return calls

        with make_server('127.0.0.1', 0, module.app, threaded=True) as server:
            print(server.server_port,flush=True)
            server.serve_forever()


if __name__ == '__main__':main()
