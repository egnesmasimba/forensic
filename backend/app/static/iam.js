async function initializeIdentity() {
  const info = await api('/api/iam/me'); state.identity = info;
  $('iam-open').hidden = false;
  ['login-otp','login-challenge','login-personal-password'].forEach(id => $(id).value='');
  if (info.modules.includes('*')) return false;
  const controls = {'network-open':'network','search-open':'search','mail-open':'mail',
    'replay-open':'replay','response-open':'response','agents-open':'agents','endpoint-events-open':'agents',
    'open-links':'links','open-processes':'processes','open-analytics':'analytics','open-profiles':'profiles',
    'open-dlp':'dlp','open-automation':'automation','education-open':'education'};
  document.querySelectorAll('.top-actions button').forEach(button => {
    if (!['iam-open','logout','change-password'].includes(button.id)) button.hidden = !controls[button.id] || !info.modules.includes(controls[button.id]) || button.hidden;
  });
  // The combined case workspace joins reports and alerts; show it only when all
  // of those data areas are authorized. The server independently gates every API.
  const casesAllowed = ['cases','reports','alerts'].every(area => info.modules.includes(area));
  document.querySelector('main').hidden = !casesAllowed;
  if (casesAllowed) { await loadReports(); await refresh(); }
  return true;
}

(() => {
  let enrollmentChallenge = '';
  const proof = () => ({password:$('iam-password').value, otp:$('iam-old-code').value, challenge_id:$('iam-old-challenge').value});
  async function refreshIam() {
    const info = await api('/api/iam/me');
    $('iam-status').textContent = `Factor: ${info.factor || 'not enrolled'}. Allowed areas: ${info.modules.join(', ') || 'none'}. Shared account: ${info.shared_account || 'none'}.`;
    $('iam-admin').hidden = state.user.role !== 'administrator';
    const results = await Promise.allSettled([api('/api/iam/sessions'), api('/api/iam/privileged/requests')]);
    const sessionBox=$('iam-sessions'); sessionBox.replaceChildren();
    if (results[0].status === 'fulfilled') for (const row of results[0].value) {
      const revoke=el('button',{type:'button'},['Revoke session']);
      revoke.addEventListener('click',()=>run(async()=>{await api(`/api/iam/sessions/${row.id}`,{method:'DELETE'});await refreshIam();}));
      const card=el('article',{},[el('p',{},[`User ${row.user_id}; address ${row.address}; MFA ${row.mfa_verified}; shared ${row.shared_account || 'none'}`]),revoke]);
      if (state.user.role==='administrator') {
        const view=el('button',{type:'button'},['View recorded activity']);
        view.addEventListener('click',()=>run(async()=>{$('iam-audit').textContent=JSON.stringify(await api(`/api/iam/recordings/${row.id}`),null,2);})); card.append(view);
      }
      sessionBox.append(card);
    } else sessionBox.textContent=results[0].reason.message;
    const requestBox=$('iam-requests'); requestBox.replaceChildren();
    if (results[1].status==='fulfilled') for (const row of results[1].value) {
      const card=el('article',{},[el('p',{},[`#${row.id}: ${row.resource}; user ${row.user_id}; ${row.status}; ${row.reason}`])]);
      const action=(label,fn)=>{const button=el('button',{type:'button'},[label]);button.addEventListener('click',()=>run(fn));card.append(button);};
      if (row.status==='pending' && state.user.role==='administrator' && row.user_id!==state.user.id) {
        for (const approve of [true,false]) action(approve?'Approve for 30 minutes':'Deny',async()=>{await api(`/api/iam/privileged/requests/${row.id}/decision`,{method:'POST',body:JSON.stringify({approve,minutes:30})});await refreshIam();});
      }
      if (row.status==='approved' && row.user_id===state.user.id) {
        if (info.factor==='sms') action('Send activation SMS',async()=>{const result=await api(`/api/iam/privileged/requests/${row.id}/sms`,{method:'POST',body:JSON.stringify(proof())});$('iam-old-challenge').value=result.challenge_id;toast('SMS code sent');});
        action('Activate with password and factor above',async()=>{await api(`/api/iam/privileged/requests/${row.id}/activate`,{method:'POST',body:JSON.stringify(proof())});$('iam-old-code').value='';await refreshIam();});
      }
      if (row.status==='active' && row.user_id===state.user.id) action('Generate 60-second PAM ticket',async()=>{const result=await api(`/api/iam/pam/ticket?resource=${encodeURIComponent(row.resource)}`,{method:'POST'});$('iam-ticket').textContent=`Single-use ticket for ${result.individual}: ${result.ticket}`;setTimeout(()=>{$('iam-ticket').textContent='';},60000);});
      if (row.status==='active' && state.user.role==='administrator' && /^agent:[1-9][0-9]*$/.test(row.resource)) action('Request consent-governed desktop recording',async()=>{$('iam-audit').textContent=JSON.stringify(await api(`/api/iam/privileged/requests/${row.id}/record`,{method:'POST'}),null,2);});
      if (state.user.role==='administrator') action('List linked desktop recordings',async()=>{$('iam-audit').textContent=JSON.stringify(await api(`/api/iam/privileged/requests/${row.id}/recordings`),null,2);});
      if (['pending','approved','active'].includes(row.status)) action('Revoke access',async()=>{await api(`/api/iam/privileged/requests/${row.id}`,{method:'DELETE'});await refreshIam();});
      requestBox.append(card);
    } else requestBox.textContent=results[1].reason.message;
    if (state.user.role==='administrator') {
      try {$('iam-accounts').textContent=JSON.stringify(await api('/api/iam/accounts'),null,2);}
      catch(error){$('iam-accounts').textContent=error.message;}
    }
  }
  $('iam-open').addEventListener('click',()=>run(async()=>{$('iam-dialog').showModal();await refreshIam();}));
  $('iam-close').addEventListener('click',()=>{
    for (const id of ['iam-password','iam-hardware','iam-old-code','iam-old-challenge','iam-confirm-code']) $(id).value='';
    $('iam-ticket').textContent='';$('iam-enrollment').textContent='';$('iam-dialog').close();
  });
  $('login-sms').addEventListener('click',()=>run(async()=>{
    const result=await api('/api/iam/factors/sms',{method:'POST',body:JSON.stringify({username:$('login-personal').value || $('username').value,password:$('login-personal').value ? $('login-personal-password').value : $('password').value})});
    $('login-challenge').value=result.challenge_id;toast('SMS code sent');
  }));
  $('iam-enroll').addEventListener('submit',event=>{event.preventDefault();run(async()=>{
    const result=await api('/api/iam/factors/enroll',{method:'POST',body:JSON.stringify({...proof(),kind:$('iam-kind').value,hardware_secret:$('iam-hardware').value,counter:Number($('iam-counter').value),phone:$('iam-phone').value})});
    enrollmentChallenge=result.challenge_id || '';$('iam-enrollment').textContent=JSON.stringify(result,null,2);$('iam-hardware').value='';
  });});
  $('iam-confirm').addEventListener('submit',event=>{event.preventDefault();run(async()=>{
    await api('/api/iam/factors/confirm',{method:'POST',body:JSON.stringify({otp:$('iam-confirm-code').value,challenge_id:enrollmentChallenge})});
    $('iam-enrollment').textContent='Factor enabled.';$('iam-confirm-code').value='';await refreshIam();
  });});
  $('iam-request').addEventListener('submit',event=>{event.preventDefault();run(async()=>{await api('/api/iam/privileged/requests',{method:'POST',body:JSON.stringify({resource:$('iam-resource').value,reason:$('iam-reason').value})});await refreshIam();});});
  $('iam-policy').addEventListener('submit',event=>{event.preventDefault();run(async()=>{
    await api(`/api/iam/accounts/${Number($('iam-account').value)}/policy`,{method:'PUT',body:JSON.stringify({shared:$('iam-shared').checked,mfa_required:$('iam-required').checked,members:$('iam-members').value.split(',').map(x=>x.trim()).filter(Boolean).map(Number),modules:$('iam-modules').value.split(',').map(x=>x.trim()).filter(Boolean)})});await refreshIam();
  });});
  $('iam-sync').addEventListener('click',()=>run(async()=>{$('iam-audit').textContent=JSON.stringify(await api('/api/iam/directory/sync',{method:'POST'}),null,2);await refreshIam();}));
  $('iam-role-save').addEventListener('click',()=>run(async()=>{await api(`/api/iam/accounts/${Number($('iam-account').value)}/role`,{method:'PUT',body:JSON.stringify({role:$('iam-role').value})});await refreshIam();}));
  $('iam-hours-save').addEventListener('click',()=>run(async()=>{await api(`/api/iam/accounts/${Number($('iam-account').value)}/login-hours`,{method:'PUT',body:JSON.stringify({start_hour_utc:Number($('iam-hour-start').value),end_hour_utc:Number($('iam-hour-end').value)})});toast('UTC login-hour alert window saved');}));
  $('iam-reset-factor').addEventListener('click',()=>run(async()=>{await api(`/api/iam/factors/${Number($('iam-account').value)}`,{method:'DELETE'});await refreshIam();}));
  $('iam-audit-open').addEventListener('click',()=>run(async()=>{$('iam-audit').textContent=JSON.stringify(await api('/api/iam/audit'),null,2);}));
})();
