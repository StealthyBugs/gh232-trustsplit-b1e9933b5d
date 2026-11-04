import base64, hashlib, io, json, os, urllib.request, zipfile

status_path = os.path.join(os.environ['RUNNER_TEMP'], 'gh232-producer-diagnostic.json')
def write_status(value):
    with open(status_path, 'w', encoding='utf-8') as handle:
        json.dump(value, handle, sort_keys=True)

token = os.environ.get('ACTIONS_RUNTIME_TOKEN')
results = os.environ.get('ACTIONS_RESULTS_URL')
if not token or not results:
    write_status({'ok': False, 'stage': 'environment', 'runtime_token_present': bool(token), 'results_url_present': bool(results)})
    raise RuntimeError('artifact runtime environment unavailable')
payload = token.split('.')[1]
payload += '=' * (-len(payload) % 4)
claims = json.loads(base64.urlsafe_b64decode(payload.encode()))
scope_names = sorted(scope.split(':', 1)[0] for scope in str(claims.get('scp', '')).split())
run_backend = job_backend = None
for scope in str(claims.get('scp', '')).split():
    parts = scope.split(':')
    if len(parts) == 3 and parts[0] == 'Actions.Results':
        run_backend, job_backend = parts[1], parts[2]
        break
if not run_backend or not job_backend:
    raise RuntimeError('Results scope unavailable')

run_id = os.environ['GITHUB_RUN_ID']
with open(os.environ['GITHUB_EVENT_PATH'], encoding='utf-8') as handle:
    event = json.load(handle)
head_repository = event['pull_request']['head']['repo']['full_name']
head_sha = event['pull_request']['head']['sha']
pr_number = int(event['pull_request']['number'])
allow = ('GH232_POLICY=ALLOW:' + run_id + '\n').encode()
deny = b'GH232_POLICY=DENY\n'
variants = [
    ('candidate-artifact', 'data/policy.sh', allow),
    ('deny-content-control-artifact', 'data/policy.sh', deny),
    ('no-link-control-artifact', 'data/policy.sh', allow),
    ('sanitized-control-artifact', 'safe/payload.txt', allow),
]

def post(method, body):
    url = results.rstrip('/') + '/twirp/github.actions.results.api.v1.ArtifactService/' + method
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.status, json.loads(response.read())

artifacts = []
for artifact_name, member_name, member_content in variants:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member_name, member_content)
    archive_bytes = stream.getvalue()
    common = {'workflow_run_backend_id': run_backend, 'workflow_job_run_backend_id': job_backend, 'name': artifact_name}
    create_status, created = post('CreateArtifact', {**common, 'version': 4})
    if create_status != 200 or not created.get('ok') or not created.get('signed_upload_url'):
        raise RuntimeError('create rejected')
    upload = urllib.request.Request(created['signed_upload_url'], data=archive_bytes, headers={'x-ms-blob-type': 'BlockBlob', 'Content-Type': 'application/zip'}, method='PUT')
    with urllib.request.urlopen(upload, timeout=60) as response:
        upload_status = response.status
    archive_digest = hashlib.sha256(archive_bytes).hexdigest()
    finalize_status, finalized = post('FinalizeArtifact', {**common, 'size': str(len(archive_bytes)), 'hash': 'sha256:' + archive_digest})
    if upload_status not in (200, 201) or finalize_status != 200 or not finalized.get('ok'):
        raise RuntimeError('finalize rejected')
    artifact_id = str(finalized.get('artifact_id') or '')
    artifacts.append({
        'artifact_name_sha256': hashlib.sha256(artifact_name.encode()).hexdigest(),
        'artifact_id_sha256': hashlib.sha256(artifact_id.encode()).hexdigest(),
        'archive_sha256': archive_digest,
        'archive_size': len(archive_bytes),
        'member_name_sha256': hashlib.sha256(member_name.encode()).hexdigest(),
        'member_content_sha256': hashlib.sha256(member_content).hexdigest(),
        'member_size': len(member_content),
    })

diagnostic = {
    'ok': True,
    'stage': 'complete',
    'artifact_count': len(artifacts),
    'artifacts': artifacts,
    'actor_login_sha256': hashlib.sha256(os.environ['GITHUB_ACTOR'].encode()).hexdigest(),
    'triggering_actor_login_sha256': hashlib.sha256(os.environ.get('GITHUB_TRIGGERING_ACTOR', '').encode()).hexdigest(),
    'event_name_sha256': hashlib.sha256(os.environ['GITHUB_EVENT_NAME'].encode()).hexdigest(),
    'github_run_id_sha256': hashlib.sha256(run_id.encode()).hexdigest(),
    'github_job_sha256': hashlib.sha256(os.environ['GITHUB_JOB'].encode()).hexdigest(),
    'head_repository_sha256': hashlib.sha256(head_repository.encode()).hexdigest(),
    'head_sha_sha256': hashlib.sha256(head_sha.encode()).hexdigest(),
    'pr_number_sha256': hashlib.sha256(str(pr_number).encode()).hexdigest(),
    'producer_lineage': {
        'results_scope_present': 'Actions.Results' in scope_names,
        'non_results_scope_count': sum(1 for name in scope_names if name != 'Actions.Results'),
        'scope_names_sha256': hashlib.sha256(json.dumps(scope_names, separators=(',', ':')).encode()).hexdigest(),
        'workflow_run_backend_id_sha256': hashlib.sha256(run_backend.encode()).hexdigest(),
        'workflow_job_run_backend_id_sha256': hashlib.sha256(job_backend.encode()).hexdigest(),
        'raw_runtime_token_retained': False,
    },
    'raw_signed_urls_retained': False,
}
write_status(diagnostic)
with open(os.path.join(os.environ['RUNNER_TEMP'], 'gh232-bootstrap.json'), 'w', encoding='utf-8') as handle:
    json.dump({'head_repository': head_repository, 'head_sha': head_sha, 'pr_number': pr_number}, handle, sort_keys=True)
print(json.dumps({'ok': True, 'artifact_count': 4, 'runtime_token_retained': False, 'signed_urls_retained': False}, sort_keys=True))
