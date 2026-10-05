$('phase3-open').addEventListener('click', () => run(async () => {
  const summary = await api('/api/biometrics/summary');
  $('biometric-summary').replaceChildren(el('p', {}, [summary.notice]), ...summary.samples.map(row => el('p', {}, [`${row.subject}: ${row.status}${row.distance !== null ? ` | deviation ${row.distance.toFixed(2)}` : ''}`])));
  $('biometric-admin').hidden = state.user.role !== 'administrator' || (state.privacy && state.privacy.enabled && !state.privacyRaw);
  $('synthetic-cohort-form').hidden = state.user.role === 'viewer';
  $('phase3-dialog').showModal();
}));
$('biometric-binding-form').addEventListener('submit', event => {
  event.preventDefault(); run(async () => {
    await api(`/api/biometrics/bindings/${Number($('biometric-agent').value)}`, {method:'PUT', body:JSON.stringify({subject:$('biometric-subject').value,enabled:$('biometric-enabled').checked})});
    $('phase3-result').textContent = 'Binding saved. Separate endpoint consent and local collector configuration are required.';
  });
});
$('biometric-samples-refresh').addEventListener('click', () => run(async () => {
  const rows = await api(`/api/biometrics/samples?subject=${encodeURIComponent($('biometric-subject').value)}`);
  $('biometric-samples').replaceChildren(...rows.map(row => el('p', {}, [`Sample ${row.id} | endpoint ${row.agent_id} | ${row.status} | ${row.metrics.key_count || 0} keystrokes | ${row.metrics.mouse_count || 0} mouse events`])));
}));
$('biometric-enroll-form').addEventListener('submit', event => {
  event.preventDefault(); run(async () => {
    await api('/api/biometrics/enroll', {method:'POST', body:JSON.stringify({subject:$('biometric-subject').value,sample_ids:$('biometric-ids').value.split(',').map(value => Number(value.trim())),threshold:Number($('biometric-threshold').value),trusted_identity_confirmed:$('biometric-trust').checked})});
    $('phase3-result').textContent = 'Trusted baseline enrolled. New samples will be compared without automatically changing the baseline.';
  });
});
$('synthetic-cohort-form').addEventListener('submit', event => {
  event.preventDefault(); run(async () => {
    const data = await api('/api/profiles/synthetic-aggregate', {method:'POST',body:JSON.stringify({subjects:$('synthetic-subjects').value.split('\n').map(value=>value.trim()).filter(Boolean)})});
    $('synthetic-cohort-result').replaceChildren(el('p', {}, [data.notice]), ...data.measures.map(row => el('p', {}, [`${row.measure.replaceAll('_',' ')}: synthetic mean ${row.synthetic_mean}`])));
  });
});
