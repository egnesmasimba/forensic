let replaySession = null, replayFrames = [], replayPosition = 0, replayNotice = "";
let responseSession = null, responseTimer = null, responseLastSequence = -1, responseBusy = false;
const responsePending = new Set();

async function loadReplaySessions() {
  const sessions = await api("/api/replay/sessions");
  if (!state.user) return;
  $("replay-session-list").replaceChildren(...sessions.map(item => el("option",{value:item.id},[`${item.title} · ${item.platform} · ${item.frames} screens`])));
  $("replay-import-section").hidden = state.user.role === "viewer";
}

function showReplayFrame() {
  const frame = replayFrames[replayPosition];
  $("replay-view").replaceChildren(); $("replay-changes").replaceChildren();
  $("replay-status").textContent = frame ? `${replaySession?.title || "Search source"} · Screen ${frame.sequence + 1} · ${new Date(frame.occurred_at).toLocaleString()} ${replayNotice}` : "No screens recorded yet.";
  $("replay-previous").disabled = !frame || (!replaySession && replayPosition === 0) || (replaySession && replayPosition === 0 && frame.sequence === 0);
  $("replay-next").disabled = !frame || (!replaySession && replayPosition === replayFrames.length - 1);
  if (!frame) return;
  if ($("replay-original").checked && frame.image_base64) {
    $("replay-view").append(el("img",{src:`data:image/jpeg;base64,${frame.image_base64}`,alt:"Original recorded screen"}));
  } else if ($("replay-original").checked && frame.original_html) {
    const page = el("iframe",{title:"Recorded original webpage",sandbox:"",referrerpolicy:"no-referrer"});
    // The restrictive policy applies before untrusted markup; scripts, forms,
    // external resources and same-origin access are disabled.
    page.srcdoc = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'">` + (frame.display_html || "");
    $("replay-view").append(page);
  } else $("replay-view").append(el("pre",{class:"terminal-screen"},[frame.text || "No reconstructed text is available for this image."]));
  if (frame.partial) $("replay-view").append(el("p",{},["Partial decoded content. Review the source capture for gaps."]));
  if (Object.keys(frame.fields).length) {
    $("replay-changes").append(el("h3",{},["Fields on this screen"]),el("dl",{},Object.entries(frame.fields).flatMap(([name,value]) => [el("dt",{},[name]),el("dd",{class:frame.changes.some(change=>change.field===name)?"field-changed":""},[value])])));
  }
  if (frame.changes.length) $("replay-changes").append(el("h3",{},["Changes from previous screen"]), ...frame.changes.map(change => el("p",{class:"field-changed"},[`${change.field}: ${change.before ?? "(absent)"} → ${change.after ?? "(removed)"}`])));
}

async function openReplaySession(id, sequence = -1) {
  replaySession = await api(`/api/replay/sessions/${id}`);
  replayFrames = await api(`/api/replay/sessions/${id}/frames?after=${Math.max(-1,sequence-1)}`);
  if (!state.user) return;
  replayPosition=0;replayNotice="";showReplayFrame();
  if (!$("replay-dialog").open) $("replay-dialog").showModal();
}

async function replaySearchResult(id) {
  const result = await api(`/api/replay/from-search/${id}`);
  if (!state.user) return;
  await loadReplaySessions();
  if (result.session) await openReplaySession(result.session.id,result.frame.sequence);
  else {
    replaySession=null;replayFrames=result.frames || [result.frame];
    replayPosition=Math.max(0,replayFrames.findIndex(frame=>frame.document_id===id));
    replayNotice=result.notice || "";showReplayFrame();
    if (!$("replay-dialog").open) $("replay-dialog").showModal();
  }
}

async function moveReplay(delta) {
  const target = replayPosition+delta;
  if (target>=0 && target<replayFrames.length) replayPosition=target;
  else if (replaySession && replayFrames.length) {
    const cursor=delta>0 ? `after=${replayFrames.at(-1).sequence}` : `before=${replayFrames[0].sequence}`;
    const page=await api(`/api/replay/sessions/${replaySession.id}/frames?${cursor}`);
    if (!state.user) return;
    if (!page.length) {toast(delta>0?"End of recording":"Start of recording");return;}
    replayFrames=page;replayPosition=delta>0?0:page.length-1;
  }
  showReplayFrame();
}

$("replay-open").addEventListener("click",()=>run(async()=>{await loadReplaySessions();if(state.user)$("replay-dialog").showModal();}));
$("replay-refresh").addEventListener("click",()=>run(loadReplaySessions));
$("replay-load").addEventListener("click",()=>run(()=>openReplaySession($("replay-session-list").value)));
$("replay-close").addEventListener("click",()=>$("replay-dialog").close());
$("replay-previous").addEventListener("click",()=>run(()=>moveReplay(-1)));
$("replay-next").addEventListener("click",()=>run(()=>moveReplay(1)));
$("replay-original").addEventListener("change",showReplayFrame);
$("replay-import-form").addEventListener("submit",event=>{event.preventDefault();run(async()=>{
  const title=$("replay-title").value,platform=$("replay-platform").value;
  if (!replaySession || replaySession.mode!=="recorded" || replaySession.title!==title || replaySession.platform!==platform) replaySession=await api("/api/replay/sessions",{method:"POST",body:JSON.stringify({title,platform})});
  // Read the last frame so appending works beyond the first loaded page.
  const last=await api(`/api/replay/sessions/${replaySession.id}/frames?before=100001&limit=1`);
  const content=$("replay-content").value,html=$("replay-is-html").checked;
  const frame=await api(`/api/replay/sessions/${replaySession.id}/frames`,{method:"POST",body:JSON.stringify({sequence:last.length?last[0].sequence+1:0,occurred_at:new Date().toISOString(),text:html?"":content,original_html:html?content:"",fields:JSON.parse($("replay-fields").value || "{}")})});
  await loadReplaySessions();await openReplaySession(replaySession.id,frame.sequence);
});});

function stopResponsePolling() {
  clearInterval(responseTimer);responseTimer=null;responseSession=null;responsePending.clear();
  $("response-desktop").removeAttribute("src");$("response-desktop").hidden=true;
}

async function sendResponse(action,argumentsValue={},confirmAction=true) {
  const agentId=$("response-agent").value,reason=$("response-reason").value.trim();
  if (reason.length<3) throw new Error("Enter a reason for this action.");
  if (["isolate","process_terminate","rollback"].includes(action) && confirmAction && !confirm(`Queue ${action.replaceAll("_"," ")} on the selected endpoint? ${action==="rollback"?(argumentsValue.scope==="windows_system"?"Windows system files/settings will be restored and this endpoint will restart in 30 seconds. Personal files are not covered.":"Captured files will be overwritten; a backup point is created first."):""}`)) return null;
  const command=await api(`/api/response/agents/${agentId}/commands`,{method:"POST",body:JSON.stringify({action,arguments:argumentsValue,reason})});
  if (!state.user) return null;
  responsePending.add(command.id);
  $("response-status").textContent=`Action #${command.id} queued. Awaiting the endpoint result.`;
  if (action==="live_start") {
    responseSession={id:command.arguments.session_id,mode:command.arguments.mode,agent_id:command.agent_id};responseLastSequence=-1;
    $("response-live").hidden=false;$("response-live-status").textContent="Waiting for local consent and endpoint acknowledgement.";
  }
  await refreshResponse();return command;
}

async function refreshResponse() {
  if (!state.user || responseBusy) return;
  responseBusy=true;
  try {
    const agentId=$("response-agent").value;
    if (!agentId) return;
    const commands=await api(`/api/response/agents/${agentId}/commands`);
    if (!state.user || agentId!==$("response-agent").value) return;
    if(commands.length) $("response-status").textContent=`Action #${commands[0].id}: ${commands[0].state.replaceAll("_"," ")}.`;
    $("response-results").replaceChildren(...commands.map(command=>{
      if (!["queued","dispatched"].includes(command.state)) responsePending.delete(command.id);
      const nodes=[el("h3",{},[`#${command.id} ${command.action.replaceAll("_"," ")} · ${command.state}`]),el("p",{},[`${command.actor}: ${command.reason}`])];
      if (command.result.error) nodes.push(el("p",{},[command.result.error]));
      if (command.result.processes) nodes.push(...command.result.processes.map(process=>{
        const row=el("p",{},[`${process.name || "Unknown"} · PID ${process.pid} · ${process.username || "Unavailable"} `]);
        if (state.user.role==="administrator" && process.pid>4 && process.create_time) {
          const button=el("button",{type:"button",class:"secondary"},["Terminate"]);
          button.addEventListener("click",()=>run(()=>sendResponse("process_terminate",{pid:process.pid,create_time:process.create_time})));row.append(button);
        }
        return row;
      }));
      if (command.result.point_id) {
        nodes.push(el("p",{},[`Rollback point ${command.result.point_id} · ${command.result.scope || "Configured files"}`]));
        if (state.user.role==="administrator") for (const [action,label] of [["verify_rollback",command.result.scope==="windows_system"?"Verify after restart":"Verify current files"],["rollback","Restore this point"]]) {
          const button=el("button",{type:"button"},[label]);button.addEventListener("click",()=>run(()=>sendResponse(action,{point_id:command.result.point_id,scope:command.result.scope==="windows_system"?"windows_system":"files"})));nodes.push(button);
        }
      }
      if (!command.result.processes && Object.keys(command.result).length) nodes.push(el("pre",{},[JSON.stringify(command.result,null,2)]));
      return el("article",{class:"content-hit"},nodes);
    }));
    const audit=await api(`/api/response/agents/${agentId}/audit`);
    if (!state.user) return;
    $("response-audit").replaceChildren(...audit.map(item=>el("p",{},[`${new Date(item.occurred_at).toLocaleString()} · ${item.actor} · ${item.action} ${item.command_id?`#${item.command_id}`:""} · ${JSON.stringify(item.detail)}`])));
    if (responseSession && String(responseSession.agent_id)===agentId) {
      const session=await api(`/api/replay/sessions/${responseSession.id}`);
      if (!state.user) return;
      responseSession={...responseSession,...session};
      $("response-live-status").textContent=`${session.status} · ${session.mode} · ${session.frames} recorded screens`;
      $("response-input").hidden=session.status!=="active" || session.mode!=="control" || session.created_by!==state.user.username;
      const frames=await api(`/api/replay/sessions/${session.id}/frames?after=${responseLastSequence}&limit=10`);
      if (!state.user) return;
      if (frames.length) {
        const frame=frames.at(-1);responseLastSequence=frame.sequence;
        $("response-desktop").src=`data:image/jpeg;base64,${frame.image_base64}`;$("response-desktop").hidden=false;
      }
      if (session.expires_at && new Date(session.expires_at)<new Date() && session.status==="active") $("response-live-status").textContent="Session time limit reached. Recording is available in Session replay.";
    }
  } finally {responseBusy=false;}
}

$("response-open").addEventListener("click",()=>run(async()=>{
  const agents=await api("/api/agents");if(!state.user)return;
  $("response-agent").replaceChildren(...agents.map(agent=>el("option",{value:agent.id},[`${agent.hostname} · ${agent.status}`])));
  $("response-actions").hidden=state.user.role!=="administrator";
  $("response-input").hidden=true;$("response-dialog").showModal();
  await refreshResponse();clearInterval(responseTimer);
  responseTimer=setInterval(()=>{if(state.user && $("response-dialog").open)run(refreshResponse);},2000);
}));
$("response-close").addEventListener("click",()=>$("response-dialog").close());
$("response-dialog").addEventListener("close",()=>{clearInterval(responseTimer);responseTimer=null;});
$("response-agent").addEventListener("change",()=>{responseSession=null;responseLastSequence=-1;$("response-live").hidden=true;run(refreshResponse);});
$("response-refresh").addEventListener("click",()=>run(refreshResponse));
$("response-actions").addEventListener("click",event=>{
  const button=event.target.closest("[data-action]");if(!button)return;
  run(()=>sendResponse(button.dataset.action,button.dataset.action==="live_start"?{mode:button.dataset.mode,duration:300}:button.dataset.scope?{scope:button.dataset.scope}:{}));
});
function remoteInput(argumentsValue) {
  if (!responseSession) throw new Error("No desktop session is active.");
  return sendResponse("control_input",{session_id:responseSession.id,...argumentsValue},false);
}
$("response-input").addEventListener("submit",event=>{event.preventDefault();run(async()=>{await remoteInput({event:"text",text:$("response-text").value});$("response-text").value="";});});
$("response-send-key").addEventListener("click",()=>run(()=>remoteInput({event:"key",key:$("response-key").value})));
$("response-scroll-up").addEventListener("click",()=>run(()=>remoteInput({event:"scroll",amount:3})));
$("response-scroll-down").addEventListener("click",()=>run(()=>remoteInput({event:"scroll",amount:-3})));
$("response-desktop").addEventListener("click",event=>{
  if(responseSession?.mode!=="control" || responseSession.status!=="active")return;
  const box=event.currentTarget.getBoundingClientRect();
  run(()=>remoteInput({event:"click",x:(event.clientX-box.left)/box.width,y:(event.clientY-box.top)/box.height}));
});
$("response-stop").addEventListener("click",()=>run(()=>sendResponse("live_stop",{session_id:responseSession.id},false)));
