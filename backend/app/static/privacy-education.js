async function initializePrivacy() {
  const status = await api('/api/privacy/status');
  state.privacy = status;
  $('privacy-open').hidden = false;
  $('education-open').hidden = false;
  const restricted = status.enabled && !state.privacyRaw;
  $('privacy-dashboard').hidden = !restricted;
  if (restricted) {
    document.querySelector('main').hidden = true;
    $('detail-panel').replaceChildren();
    $('case-list').replaceChildren();
    document.querySelectorAll('.top-actions button').forEach(button => {
      if (!['privacy-open', 'education-open', 'phase3-open', 'iam-open', 'logout', 'change-password', 'manage-users'].includes(button.id)) button.hidden = true;
    });
    const data = await api('/api/privacy/dashboard');
    $('privacy-counts').replaceChildren(el('h3', {}, ['Aggregate overview']), el('p', {}, [data.suppression]), ...data.aggregates.map(row => el('p', {}, [`${row.severity}: ${row.event_range} events`])), el('h3', {}, ['Pseudonymized endpoint counts']), ...data.subjects.map(row => el('p', {}, [`${row.subject}: ${row.events} ${row.severity} events`])));
    if (!data.subjects.length) $('privacy-counts').append(el('p', {}, ['No endpoint activity to display.']));
  }
  return restricted;
}

$('privacy-open').addEventListener('click', () => run(async () => {
  const admin = state.user.role === 'administrator';
  ['privacy-form', 'privacy-admin-actions', 'privacy-raw-label'].forEach(id => $(id).hidden = !admin);
  $('privacy-records').replaceChildren();
  $('privacy-result').textContent = state.privacy.notice;
  if (admin) {
    const data = await api('/api/privacy/settings');
    for (const [id, key] of [['privacy-enabled','enabled'],['privacy-consent','consent_required'],['privacy-council','council_required'],['privacy-auto','automatic_retention']]) $(id).checked = data[key];
    for (const [id, key] of [['privacy-purpose','purpose'],['privacy-basis','legal_basis'],['privacy-reference','council_reference'],['privacy-days','retention_days']]) $(id).value = data[key];
    if (data.council_expires_at) {
      const date = new Date(data.council_expires_at);
      $('privacy-expiry').value = new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16);
    } else $('privacy-expiry').value = '';
    $('privacy-raw').checked = !!state.privacyRaw;
  }
  const media = await api('/api/privacy/media');
  const mediaBox = $('privacy-media'); mediaBox.replaceChildren(el('h3', {}, ['Masked evidence previews']));
  for (const kind of ['screenshots', 'recordings']) for (const id of media[kind]) {
    const button = el('button', {type:'button', class:'secondary'}, [`${kind === 'screenshots' ? 'Screenshot' : 'Recording'} ${id}`]);
    button.addEventListener('click', () => run(async () => {
      const data = await api(kind === 'screenshots' ? `/api/privacy/screenshots/${id}` : `/api/privacy/recordings/${id}/frames`);
      const items = kind === 'screenshots' ? [data] : data;
      $('privacy-preview-media').replaceChildren(...items.map(item => el('article', {}, [el('p', {}, [item.mask]), ...(item.image_base64 ? [el('img', {src:`data:image/jpeg;base64,${item.image_base64}`, style:'max-width:100%', alt:'Privacy masked image'})] : [])])));
    }));
    mediaBox.append(button);
  }
  $('privacy-dialog').showModal();
}));
$('privacy-form').addEventListener('submit', event => {
  event.preventDefault(); run(async () => {
    await api('/api/privacy/settings', {method:'PUT', body:JSON.stringify({enabled:$('privacy-enabled').checked, consent_required:$('privacy-consent').checked, council_required:$('privacy-council').checked, council_reference:$('privacy-reference').value, council_expires_at:$('privacy-expiry').value ? new Date($('privacy-expiry').value).toISOString() : null, purpose:$('privacy-purpose').value, legal_basis:$('privacy-basis').value, retention_days:Number($('privacy-days').value), automatic_retention:$('privacy-auto').checked})});
    $('privacy-dialog').close(); await signedIn(state.user);
  });
});
$('privacy-raw').addEventListener('change', () => run(async () => {
  state.privacyRaw = $('privacy-raw').checked;
  $('privacy-dialog').close(); await signedIn(state.user);
}));
$('privacy-preview').addEventListener('click', () => run(async () => {
  const data = await api('/api/privacy/retention?dry_run=true', {method:'POST'});
  $('privacy-result').textContent = `${data.events} endpoint payloads and ${data.frames} recorded frames, ${data.biometric_samples || 0} biometric samples and ${data.biometric_profiles || 0} biometric profiles will expire. ${data.scope}. Applying retention permanently removes their content.`;
  $('privacy-apply').disabled = !data.events && !data.frames && !data.biometric_samples && !data.biometric_profiles;
}));
$('privacy-apply').addEventListener('click', () => run(async () => {
  const data = await api('/api/privacy/retention?dry_run=false', {method:'POST'});
  $('privacy-result').textContent = `Expired ${data.events} payloads, ${data.frames} frames, ${data.biometric_samples || 0} biometric samples and ${data.biometric_profiles || 0} biometric profiles.`;
  $('privacy-apply').disabled = true;
}));
function privacyRecordList(target, rows) {
  $(target).replaceChildren(...rows.map(row => {
    if (row.action) return el('article', {class:'note'}, [
      el('strong', {}, [row.action.replaceAll('_', ' ')]),
      el('p', {}, [`${row.actor} | ${formatWhen(row.created_at)}${row.warning_id ? ` | warning ${row.warning_id}` : ''}`]),
      ...(row.detail && row.detail.path ? [el('p', {}, [`Raw information accessed: ${row.detail.path}`])] : [])
    ]);
    if (typeof row.granted === 'boolean') return el('article', {class:'note'}, [
      el('strong', {}, [`Endpoint ${row.agent_id}: consent ${row.granted ? 'granted' : 'withdrawn'}`]),
      el('p', {}, [row.purpose]), el('p', {}, [`Expires ${formatWhen(row.expires_at)}`])
    ]);
    return el('article', {class:'note'}, [el('strong', {}, [`Warning ${row.id}: ${row.title}`]),
      el('p', {}, [row.message]), el('p', {}, [row.education]),
      el('p', {}, [`Endpoint ${row.agent_id} | level ${row.level} | ${row.state} | training ${row.training_state}`]),
      ...(row.training_url ? [el('a', {href:row.training_url, target:'_blank', rel:'noopener noreferrer'}, ['Open assigned training'])] : [])]);
  }));
  if (!rows.length) $(target).append(el('p', {}, ['No records yet.']));
}
$('privacy-audit-open').addEventListener('click', () => run(async () => {
  const consents = await api('/api/privacy/consents');
  const audit = await api('/api/privacy/audit');
  privacyRecordList('privacy-records', [...consents, ...audit]);
}));
$('education-open').addEventListener('click', () => run(async () => {
  const admin = state.user.role === 'administrator';
  $('education-form').hidden = !admin; $('education-reminder').hidden = !admin;
  $('education-warnings').replaceChildren(); $('education-audit').replaceChildren();
  if (admin) {
    const policy = await api('/api/education/policy');
    $('education-enabled').checked = policy.enabled;
    for (const [id, key] of [['education-title','title'],['education-message','message'],['education-guidance','education'],['education-training','training_url'],['education-manager','manager'],['education-escalate','escalation_count'],['education-minutes','reminder_minutes']]) $(id).value = policy[key];
    privacyRecordList('education-warnings', await api('/api/education/warnings'));
    privacyRecordList('education-audit', await api('/api/education/audit'));
  }
  const notices = await api('/api/education/inbox');
  $('education-inbox').replaceChildren(...notices.map(notice => {
    const node = el('article', {class:'note'}, [el('strong', {}, [notice.subject]), el('p', {}, [notice.body])]);
    if (!notice.acknowledged) {
      const ack = el('button', {type:'button'}, ['Acknowledge']);
      ack.addEventListener('click', () => run(async () => { await api(`/api/education/inbox/${notice.id}/ack`, {method:'POST'}); ack.disabled = true; }));
      node.append(ack);
    }
    return node;
  }));
  $('education-dialog').showModal();
}));
$('education-form').addEventListener('submit', event => {
  event.preventDefault(); run(async () => {
    await api('/api/education/policy', {method:'PUT', body:JSON.stringify({enabled:$('education-enabled').checked, title:$('education-title').value, message:$('education-message').value, education:$('education-guidance').value, training_url:$('education-training').value, manager:$('education-manager').value, escalation_count:Number($('education-escalate').value), reminder_minutes:Number($('education-minutes').value)})});
    toast('Notification policy saved.');
  });
});
$('education-reminder').addEventListener('submit', event => {
  event.preventDefault(); run(async () => {
    await api(`/api/education/reminders/${Number($('education-agent').value)}`, {method:'POST'}); toast('Reminder queued for the endpoint.');
  });
});
async function loadApplicationRules() {
  const rows = await api('/api/applications/rules');
  $('application-rules').replaceChildren(...rows.map(row => {
    const article = el('article', {class:'note'}, [el('strong', {}, [row.name]), el('p', {}, [`${row.field} contains ${row.pattern} | score ${row.score}`])]);
    const remove = el('button', {type:'button'}, ['Remove']);
    remove.addEventListener('click', () => run(async () => { await api(`/api/applications/rules/${row.id}`, {method:'DELETE'}); await loadApplicationRules(); }));
    article.append(remove);
    return article;
  }));
}
$('applications-open').addEventListener('click', () => run(async () => { await loadApplicationRules(); $('applications-dialog').showModal(); }));
$('application-form').addEventListener('submit', event => {
  event.preventDefault(); run(async () => {
    await api('/api/applications/rules', {method:'POST', body:JSON.stringify({name:$('application-name').value, field:$('application-field').value, pattern:$('application-pattern').value, score:Number($('application-score').value)})});
    $('application-form').reset(); $('application-score').value = '40'; await loadApplicationRules();
  });
});
