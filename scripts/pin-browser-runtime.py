# Regenerate measured archive and file hashes from the exact upstream payloads.
# Review all source/version changes and the resulting lock diff before committing.
import concurrent.futures,subprocess,hashlib,tarfile,zipfile,io,json,pathlib
assets=[('driver','https://registry.npmjs.org/playwright-core/-/playwright-core-1.62.1.tgz','tgz','package/'),('node','https://nodejs.org/dist/v24.19.0/node-v24.19.0-linux-x64.tar.gz','tgz','node-v24.19.0-linux-x64/bin/node'),('browser','https://cdn.playwright.dev/builds/cft/151.0.7922.34/linux64/chrome-headless-shell-linux64.zip','zip','')]
import tempfile
cache=tempfile.TemporaryDirectory(prefix='auth-refresh-pin-')
root=pathlib.Path(cache.name)
def fetch(asset):
 name,url,kind,prefix=asset;p=root/name
 if not p.exists():subprocess.run(['curl','--fail','--location','--silent','--show-error','--max-time','120','--output',str(p),url],check=True)
 data=p.read_bytes();files={};entries={}
 if kind=='tgz':
  with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as a:
   for e in a:
    if not e.isfile():continue
    if name=='node' and e.name!=prefix:continue
    if name=='driver' and not e.name.startswith(prefix):continue
    path='driver/node' if name=='node' else 'driver/'+e.name
    entries[path]=(a.extractfile(e).read(),e.mode)
 else:
  with zipfile.ZipFile(io.BytesIO(data)) as a:
   for e in a.infolist():
    if e.is_dir():continue
    entries['browser/chromium_headless_shell-1234/'+e.filename]=(a.read(e), (e.external_attr>>16)&0o777)
 for path,(b,mode) in entries.items():
  files[path]={'sha256':hashlib.sha256(b).hexdigest(),'mode':mode&0o777}
  if path.endswith('/coreBundle.js'):
   patched=b
   for old,new in [(b'pageError.location.url',b'pageError.location?.url || ""'),(b'pageError.location.lineNumber',b'pageError.location?.lineNumber || 0'),(b'pageError.location.columnNumber',b'pageError.location?.columnNumber || 0')]:patched=patched.replace(old,new)
   files[path]['patched_sha256']=hashlib.sha256(patched).hexdigest()
 return {'name':name,'url':url,'sha256':hashlib.sha256(data).hexdigest(),'format':kind,'prefix':prefix},files
r=list(concurrent.futures.ThreadPoolExecutor(max_workers=3).map(fetch,assets));lock={'platform':'linux_amd64','playwright':'1.62.1','browser_dir':'chromium_headless_shell-1234','assets':[a for a,f in r],'files':{k:v for a,f in r for k,v in f.items()}}
(pathlib.Path(__file__).resolve().parent.parent/'internal/browserruntime/lock.json').write_text(json.dumps(lock,indent=2)+'\n')
print('Pinned',len(lock['files']),'runtime files across',len(r),'verified-source archives')
