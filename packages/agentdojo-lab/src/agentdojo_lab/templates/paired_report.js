'use strict';
const data = JSON.parse(document.getElementById('paired-event-data').textContent);
const $ = id => document.getElementById(id);
const ns = 'http://www.w3.org/2000/svg';
const colors = [{ink:'#087d7b',fill:'#edf8f4',line:'#acd3c7'}, {ink:'#b64b43',fill:'#fff3ed',line:'#e7bbab'}];
const arms = ['clean','attacked'];
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const pretty = value => typeof value === 'string' ? value : JSON.stringify(value,null,2);
const short = (value,n=44) => {const s=String(value ?? '').replace(/\s+/g,' ').trim();return s.length>n?s.slice(0,n-1)+'…':s;};
const number = id => id ? String(id).replace(/^event:0*/,'') || '0' : '—';
const eventAt = (row,arm) => {const i=row[arms[arm]+'_index'];return i == null?null:data.arms[arm].events[i];};
const defaultRow = data.first_security_row ?? data.rows.find(r=>r.changed&&r.phase==='response')?.index ?? data.first_changed_row ?? 0;
let selected = defaultRow, currentTab='compare', overviewSources=[];

function svgNode(tag,attrs={},text){const n=document.createElementNS(ns,tag);for(const [key,value] of Object.entries(attrs))n.setAttribute(key,String(value));if(text!==undefined)n.textContent=text;return n;}
function svgText(parent,x,y,text,attrs={}){parent.append(svgNode('text',{x,y,fill:'#243e4b','font-size':12,...attrs},text));}
function buttonNode(group,callback,label){group.setAttribute('role','button');group.setAttribute('tabindex','0');group.setAttribute('aria-label',label);group.addEventListener('click',callback);group.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();callback();}});}
function findRow(arm,id){return data.rows.find(r=>r[arms[arm]+'_event_id']===id);}
function goEvent(arm,id){const row=findRow(arm,id);if(row){selectRow(row.index,true);$('event-comparison').scrollIntoView({block:'nearest',behavior:'smooth'});}}
function eventSummary(event){
 let args=event.data?.arguments||event.data?.runtime_input_args;
 const call=event.comparison_data?.body?.choices?.[0]?.message?.tool_calls?.[0]?.function;
 if(!args&&call)args=call.arguments;
 if(args?.recipients)return 'To '+args.recipients.join(', ')+(args.attachments?.length?' · '+args.attachments.length+' attachment'+(args.attachments.length===1?'':'s'):'');
 if(args?.filename)return String(args.filename);
 const filename=String(event.content||'').match(/(?:^|\n)\s*filename:\s*([^\n]+)/);
 if(filename)return filename[1].replace(/^['"]|['"]$/g,'');
 if(event.event_type==='ENVIRONMENT_CHANGE')return 'Observed state after '+(event.function||'the tool call');
 return event.summary;
}

function buildHeader(){
 $('run-identities').innerHTML=data.arms.map((arm,i)=>`<div class="identity ${i?'attack-arm':'clean-arm'}"><strong class="${i?'attacked':'clean'}-text">${i?'Attacked':'Clean'}</strong><div><div class="run-name">${esc(arm.run_id)}</div><div class="identity-meta">${esc(arm.model || 'Model not recorded')} · ${esc(arm.status || 'Status unknown')}</div></div></div>`).join('');
 const sensitive=data.rows.filter(r=>r.security_relevant), proposals=data.rows.filter(r=>r.event_type==='TOOL_CALL_PROPOSED');
 const failed=data.arms.filter(a=>a.native_tasks?.some(t=>t.utility===false)).length;
 const unknown=data.arms.some(a=>!a.native_tasks?.length||a.native_tasks.some(t=>typeof t.utility!=='boolean'));
 const metrics=[['Recorded events',data.arms.map(a=>a.events.length).join(' / '),'Clean / attacked'],['Tool proposals',proposals.length,'Aligned action rows'],['Changed sensitive calls',sensitive.length,'Configured argument paths'],['Task utility',failed?failed+' / 2 failed':unknown?'Unknown':'2 / 2 passed','Saved native task evaluation']];
 $('metrics').innerHTML=metrics.map(([label,value,note])=>`<article class="metric"><p class="metric-label">${esc(label)}</p><p class="metric-value">${esc(value)}</p><p class="metric-note">${esc(note)}</p></article>`).join('');
 $('alignment-note').textContent='Event alignment is a display hypothesis. '+data.alignment.rule+' '+data.alignment.limitations;
 if(data.comparability?.status!=='comparable_under_recorded_checks'||data.alignment.proposal_status==='ambiguous'){
  $('comparison-status').hidden=false;$('comparison-status').textContent='Comparison is unconfirmed or alignment is ambiguous. Highlighted differences are inspection candidates. '+(data.comparability?.reasons||[]).join('; ');
 }
 $('jump-divergence').disabled=data.first_security_row==null;
}

function pairSources(events){
 const groups=new Map();
 for(let arm=0;arm<2;arm++)for(const source of events[arm]?.sources||[]){
  const anchor=findRow(arm,source.exposure_event_id)||findRow(arm,source.source_result_event_id);
  const key=anchor?'row:'+anchor.index:'unresolved:'+arm+':'+groups.size;
  if(!groups.has(key))groups.set(key,[null,null]);
  groups.get(key)[arm]=source;
 }
 // The most visibly different source comes first for reading, never as a causal ranking.
 return [...groups.values()].sort((a,b)=>sourceDifference(b)-sourceDifference(a));
}
function sourceDifference(pair){
 if(!pair.every(Boolean))return 0;
 const left=String(pair[0].content||''),right=String(pair[1].content||'');
 if(left===right)return 0;
 let start=0,end=0;while(start<left.length&&start<right.length&&left[start]===right[start])start++;
 while(end<left.length-start&&end<right.length-start&&left.at(-end-1)===right.at(-end-1))end++;
 return Math.max(left.length,right.length)-start-end;
}
function focusProposal(arm){
 const events=data.arms[arm].events,row=data.rows[defaultRow];if(!row)return null;
 const event=eventAt(row,arm);
 return event?.event_type==='TOOL_CALL_PROPOSED'?event:events.find(e=>e.event_type==='TOOL_CALL_PROPOSED');
}
function setupOverviewSources(){
 overviewSources=pairSources([focusProposal(0),focusProposal(1)]);
 $('overview-source').innerHTML=overviewSources.map((pair,i)=>`<option value="${i}">${esc(pair[0]?.function||pair[1]?.function||'Tool result')} · ${esc(number(pair[0]?.source_result_event_id))} / ${esc(number(pair[1]?.source_result_event_id))}</option>`).join('')||'<option>No recorded source</option>';
}
function overviewStages(arm){
 const events=data.arms[arm].events, row=data.rows[defaultRow];
 if(!row)return [];
 const proposal=focusProposal(arm);
 if(!proposal)return [];
 const request=proposal.resolved_request_id||proposal.model_request_id;
 const source=overviewSources[Number($('overview-source').value)]?.[arm];
 const get=id=>events.find(e=>e.event_id===id);
 const response=events.findLast(e=>e.event_type==='MODEL_RESPONSE'&&e.model_request_id===request&&e.event_sequence<proposal.event_sequence);
 const returned=events.find(e=>e.event_type==='TOOL_RUNTIME_RETURNED'&&e.call_ref===proposal.call_ref);
 const state=events.find(e=>e.event_type==='ENVIRONMENT_CHANGE'&&e.call_ref===proposal.call_ref);
 return [get(source?.source_result_event_id),get(source?.exposure_event_id),response,proposal,returned,state];
}
function drawOverview(){
 const svg=$('path-overview');svg.replaceChildren();
 const defs=svgNode('defs');for(let a=0;a<2;a++){const marker=svgNode('marker',{id:'overview-arrow-'+a,viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:5,markerHeight:5,orient:'auto-start-reverse'});marker.append(svgNode('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:colors[a].line}));defs.append(marker);}svg.append(defs);
 const labels=['Source result','Exposed in request','Model response','Tool proposal','Runtime return','State change'];
 labels.forEach((label,i)=>svgText(svg,149+i*177,20,label,{'text-anchor':'middle','font-size':10,fill:'#6f838b','font-weight':600}));
 for(let a=0;a<2;a++){
  const y=43+a*94,items=overviewStages(a),c=colors[a];svgText(svg,4,y+26,a?'ATTACKED':'CLEAN',{'font-size':9,'font-weight':800,fill:c.ink});
  for(let i=0;i<6;i++){
   const x=74+i*177,event=items[i];if(i<5)svg.append(svgNode('line',{x1:x+149,y1:y+29,x2:x+176,y2:y+29,stroke:c.line,'stroke-width':2,'stroke-dasharray':i===0?'4 3':'none','marker-end':'url(#overview-arrow-'+a+')'}));
   const group=svgNode('g',{class:'overview-node'});group.append(svgNode('rect',{x,y,width:149,height:63,rx:9,fill:event?c.fill:'#f6f8f9',stroke:event?c.line:'#d9e0e3','stroke-dasharray':event?'none':'4 3'}));
   if(event){svgText(group,x+11,y+19,'EVENT '+number(event.event_id),{'font-size':9,fill:c.ink,'font-weight':700});svgText(group,x+11,y+38,short(event.function||event.title,21),{'font-size':11,'font-weight':650});svgText(group,x+11,y+53,short(eventSummary(event),24),{'font-size':8,fill:'#6f838b'});buttonNode(group,()=>goEvent(a,event.event_id),(a?'Attacked':'Clean')+' '+event.event_id+' '+event.title);}else{svgText(group,x+11,y+29,'Not recorded',{'font-size':11,fill:'#8b969d'});svgText(group,x+11,y+46,'Evidence unavailable',{'font-size':9,fill:'#8b969d'});}svg.append(group);
  }
 }
}

function visibleRows(){
 const mode=$('event-filter').value,q=$('event-search').value.trim().toLowerCase();
 return data.rows.filter(row=>{
  const phase= mode==='all'||(mode==='changed'&&row.changed)||(mode==='source'&&row.phase==='source')||(mode==='actions'&&['action','execution','state'].includes(row.phase))||(mode==='key'&&['TOOL_RESULT','TOOL_OUTPUT_EXPOSED','MODEL_RESPONSE','TOOL_CALL_PROPOSED','TOOL_RUNTIME_RETURNED','ENVIRONMENT_CHANGE'].includes(row.event_type));
  const matches=!q||[row.title,row.clean_event_id,row.attacked_event_id,...[0,1].map(a=>eventAt(row,a)?.summary||'')].join(' ').toLowerCase().includes(q);
  return phase&&matches;
 });
}
function drawGraph(scroll=false){
 const svg=$('event-graph'),rows=visibleRows();svg.replaceChildren();svg.setAttribute('viewBox',`0 0 520 ${Math.max(130,rows.length*91+22)}`);$('empty-graph').hidden=rows.length!==0;$('visible-count').textContent=rows.length+' of '+data.rows.length+' event pairs';
 for(let a=0;a<2;a++){const x=a?279:13,c=colors[a];let previous=null;rows.forEach((row,i)=>{const event=eventAt(row,a),y=12+i*91;if(previous!==null&&event){svg.append(svgNode('path',{d:`M ${x+114} ${previous+65} L ${x+114} ${y-5}`,class:'graph-link '+arms[a]}));svg.append(svgNode('path',{d:`M ${x+110} ${y-9} L ${x+114} ${y-3} L ${x+118} ${y-9}`,fill:'none',stroke:c.line,'stroke-width':1.7}));}if(event)previous=y;});}
 rows.forEach((row,i)=>{
  const y=12+i*91;
  if(row.changed){svg.append(svgNode('line',{x1:241,y1:y+32,x2:279,y2:y+32,stroke:'#d7a24a','stroke-dasharray':'3 3'}));svg.append(svgNode('circle',{cx:260,cy:y+32,r:9,fill:'#fff0ce',stroke:'#eacb89'}));svgText(svg,260,y+36,'Δ',{'font-size':10,'text-anchor':'middle',fill:'#936100'});}
  for(let a=0;a<2;a++){
   const x=a?279:13,event=eventAt(row,a),c=colors[a],group=svgNode('g',{class:'graph-node'+(selected===row.index?' selected':''),'data-row':row.index,'data-arm':arms[a]});
   group.append(svgNode('rect',{x,y,width:228,height:65,rx:9,fill:!event?'#f7f8f9':selected===row.index?c.fill:'#fff',stroke:!event?'#d7dfe2':selected===row.index?c.ink:row.changed?'#d9ba80':c.line,'stroke-dasharray':event?'none':'4 3'}));
   if(event){svgText(group,x+12,y+18,'EVENT '+number(event.event_id),{'font-size':9,'font-weight':700,fill:c.ink});svgText(group,x+12,y+36,short(event.title,32),{'font-size':12,'font-weight':650});svgText(group,x+12,y+53,short(eventSummary(event),39),{'font-size':9,fill:'#73848e'});}else{svgText(group,x+12,y+28,'No aligned event',{'font-size':11,fill:'#7d8d97'});svgText(group,x+12,y+46,a?'Missing from attacked':'Only in attacked',{'font-size':9,fill:'#87959c'});}
   buttonNode(group,()=>selectRow(row.index),(a?'Attacked':'Clean')+' '+(event?event.event_id+' '+event.title:'missing event'));group.setAttribute('aria-pressed',String(selected===row.index));group.append(svgNode('title',{},event?event.event_id+' · '+event.event_type+'\n'+event.summary:'No corresponding recorded event'));svg.append(group);
  }
 });
 if(scroll){const i=rows.findIndex(row=>row.index===selected);if(i>=0){const box=$('event-list'),scale=svg.getBoundingClientRect().width/520;box.scrollTo({top:Math.max(0,i*91*scale-box.clientHeight/3),behavior:'instant'});}}
}

function tokenDiff(before,after){
 const l=String(before??'').match(/\s+|[^\s]+/g)||[],r=String(after??'').match(/\s+|[^\s]+/g)||[];
 if(before===after)return [esc(before),esc(after)];
 let prefix=0,suffix=0;while(prefix<l.length&&prefix<r.length&&l[prefix]===r[prefix])prefix++;
 while(suffix<l.length-prefix&&suffix<r.length-prefix&&l[l.length-1-suffix]===r[r.length-1-suffix])suffix++;
 const a=l.slice(prefix,l.length-suffix),b=r.slice(prefix,r.length-suffix);
 let left=[],right=[];
 if(a.length*b.length<180000){
  const matrix=Array.from({length:a.length+1},()=>new Uint16Array(b.length+1));
  for(let i=a.length-1;i>=0;i--)for(let j=b.length-1;j>=0;j--)matrix[i][j]=a[i]===b[j]?matrix[i+1][j+1]+1:Math.max(matrix[i+1][j],matrix[i][j+1]);
  let i=0,j=0;while(i<a.length||j<b.length){if(i<a.length&&j<b.length&&a[i]===b[j]){left.push(esc(a[i++]));right.push(esc(b[j++]));}else if(i<a.length&&(j===b.length||matrix[i+1][j]>=matrix[i][j+1]))left.push('<mark>'+esc(a[i++])+'</mark>');else right.push('<mark>'+esc(b[j++])+'</mark>');}
 }else{left=['<mark>'+esc(a.join(''))+'</mark>'];right=['<mark>'+esc(b.join(''))+'</mark>'];}
 const head=esc(l.slice(0,prefix).join('')),tail=esc(suffix?l.slice(l.length-suffix).join(''):'');
 return [head+left.join('')+tail,head+right.join('')+tail];
}
function flatten(value,path='',output=new Map()){
 if(value!==null&&typeof value==='object'&&Object.keys(value).length){for(const [k,v] of Object.entries(value))flatten(v,path+'/'+k.replaceAll('~','~0').replaceAll('/','~1'),output);}else output.set(path||'/',value);return output;
}
function fieldName(path){
 const parts=path.split('/').filter(Boolean),key=parts.at(-1)||'Recorded content';
 const labels={recipients:'Recipient',body:'Message body',content:'Content',subject:'Subject',function:'Tool',name:'Tool',file_id:'File attachment',attachments:'Attachments',result:'Returned result',error:'Runtime error',status:'Status',role:'Message role'};
 const chosen=/^\d+$/.test(key)?parts.at(-2):key;
 return labels[chosen]||chosen.replaceAll('_',' ').replace(/^./,c=>c.toUpperCase());
}
function fieldHtml(change){
 const missing='<span class="absent">Not present</span>',left=change.before_present?pretty(change.before):null,right=change.after_present?pretty(change.after):null;
 const highlighted=change.before_present&&change.after_present?tokenDiff(left,right):[change.before_present?'<mark>'+esc(left)+'</mark>':missing,change.after_present?'<mark>'+esc(right)+'</mark>':missing];
 const isChanged=change.kind!=='same';
 const type=value=>value===null?'null':Array.isArray(value)?'array':typeof value;
 const typeNote=change.before_present&&change.after_present&&type(change.before)!==type(change.after)?`<p class="type-note">Type changed: ${esc(type(change.before))} → ${esc(type(change.after))}</p>`:'';
 return `<div class="field-row ${isChanged?'is-changed':''}"><div class="field-label">${esc(fieldName(change.path))}${isChanged?`<span class="change-tag">${esc(change.kind)}</span>`:''}</div><div class="field-values"><div class="value-cell">${highlighted[0]}</div><div class="value-cell">${highlighted[1]}</div></div>${typeNote}<p class="type-note"><code>${esc(change.path||'/')}</code></p></div>`;
}
function renderComparison(row){
 const events=[eventAt(row,0),eventAt(row,1)],left=flatten(events[0]?.comparison_data),right=flatten(events[1]?.comparison_data);
 const changes=row.changes||[];
 $('difference-summary').classList.toggle('same',!changes.length);
 $('difference-summary').textContent=changes.length?changes.length+' recorded field difference'+(changes.length===1?'':'s')+(row.security_relevant?' · includes a configured sensitive argument':''): 'Same recorded content. Run identifiers and transport metadata are available under Raw evidence.';
 $('readable-comparison').innerHTML=changes.map(fieldHtml).join('');
 const shared=[...left.keys()].filter(path=>right.has(path)&&JSON.stringify(left.get(path))===JSON.stringify(right.get(path))).map(path=>({path,before_present:true,after_present:true,before:left.get(path),after:right.get(path),kind:'same'}));
 // Put useful content first; identical empty fields remain inspectable in raw evidence.
 const readable=shared.filter(c=>c.before!==null&&c.before!==''&&!['/body/object','/body/model','/status_code'].includes(c.path));
 if(!changes.length){
  const focus=readable.filter(c=>/arguments|content|result|function|message|error/.test(c.path));
  const preferred=focus.length?focus.slice(0,10):readable.slice(0,8);
  $('readable-comparison').innerHTML=preferred.map(fieldHtml).join('')||'<div class="empty-state">No additional readable content in this event. Open Raw evidence for its exact record.</div>';
 }
 $('shared-fields').innerHTML=readable.map(fieldHtml).join('')||'<p class="empty-state">No shared content fields.</p>';
 $('other-fields').hidden=!changes.length||!readable.length;$('other-fields').open=false;
 $('raw-comparison').innerHTML=events.map((event,a)=>`<article class="raw-card"><h3 class="${a?'attacked':'clean'}-text">${a?'Attacked':'Clean'} · ${esc(event?.event_id||'Absent')}</h3><pre>${esc(event?JSON.stringify(Object.fromEntries(Object.entries(event).filter(([k])=>!['comparison_data','display_metadata','sources','content','summary','title','phase','source_status','function','resolved_request_id'].includes(k))),null,2):'No aligned event')}</pre><details><summary>Display metadata</summary><pre>${esc(JSON.stringify(event?.display_metadata||{},null,2))}</pre></details></article>`).join('');
 renderSources(events);
}

function renderSources(events){
 const sources=pairSources(events),max=sources.length;
 if(!max){$('source-comparison').innerHTML='<div class="empty-state">No linked outbound source exposure is recorded for this event. Source influence remains unknown.</div>';return;}
 let content='';
 for(let i=0;i<max;i++){
  const items=sources[i],before=items[0]?.content,after=items[1]?.content;
  const values=items.every(Boolean)?tokenDiff(before,after):items.map(s=>s?esc(s.content):'<span class="absent">No aligned source exposure</span>');
  content+=`<article class="source-block"><h3 class="source-title">${esc(items[0]?.function||items[1]?.function||'Recorded tool source')}</h3><div class="pair-grid">`;
  for(let a=0;a<2;a++){
   const s=items[a];content+=`<div><strong class="${a?'attacked':'clean'}-text">${a?'Attacked source evidence':'Clean source evidence'}</strong>`;
   if(s){content+=`<div class="source-refs"><span>Result</span><button type="button" data-source-arm="${a}" data-source-id="${esc(s.source_result_event_id||'')}">${esc(s.source_result_event_id||'Unresolved')}</button><span>→ exposure</span><button type="button" data-source-arm="${a}" data-source-id="${esc(s.exposure_event_id||'')}">${esc(s.exposure_event_id||'Unrecorded')}</button></div><div class="value-cell">${values[a]}</div><p class="source-status">${esc(s.relation?.replaceAll('_',' ')||'Recorded source association')} · ${esc(s.resolution_status)}</p><p class="source-status">Request: ${esc(s.model_request_id||'Unknown')}</p>`;}else content+='<p class="empty-state">No corresponding source evidence</p>';
   content+='</div>';
  }
  content+='</div></article>';
 }
 $('source-comparison').innerHTML=content;
 $('source-comparison').querySelectorAll('button[data-source-id]').forEach(button=>button.addEventListener('click',()=>goEvent(Number(button.dataset.sourceArm),button.dataset.sourceId)));
}

const explanations={
 TOOL_OUTPUT_EXPOSED:'This content was included in the outbound model request. Compare the actual clean and attacked source text below.',
 TOOL_RESULT:'A tool result was recorded here. Its appearance in a later model request is a separate exposure event.',
 MODEL_RESPONSE:'This is the recorded model response. Tool-call arguments are expanded for comparison; the original response is preserved under Raw evidence.',
 TOOL_CALL_PROPOSED:'The parser produced this proposed tool call. Compare its argument values below; runtime return and state change nodes show later execution evidence.',
 TOOL_RUNTIME_RETURNED:'The recorded tool runtime returned. Error fields and returned values are shown here; state changes are separate evidence.',
 ENVIRONMENT_CHANGE:'The recorder captured an environment change after the tool call. Differences here describe observed state, not causal attribution.',
 MODEL_REQUEST:'This is the outbound request assembled from the recorded conversation. Open Sources to inspect each linked tool output.'
};
function selectTab(name){currentTab=name;for(const tab of ['compare','sources','evidence']){$('tab-'+tab).setAttribute('aria-selected',String(tab===name));$('tab-'+tab).tabIndex=tab===name?0:-1;$('panel-'+tab).hidden=tab!==name;}}
function selectRow(index,scroll=false){
 const row=data.rows[index];if(!row)return;selected=index;
 $('selection-kind').textContent=row.event_type.replaceAll('_',' ');
 $('selection-title').textContent=row.title;
 $('selection-badge').textContent=row.status==='same'?'Same content':row.status==='changed'?'Content differs':'Unmatched event';$('selection-badge').classList.toggle('changed',row.changed);
 const ids='Clean '+(row.clean_event_id||'absent')+' · Attacked '+(row.attacked_event_id||'absent')+'. ';
 $('selection-explanation').textContent=ids+(explanations[row.event_type]||'Inspect this recorded event alongside its aligned counterpart.');
 renderComparison(row);drawGraph(scroll);selectTab(currentTab);
}

function openHash(){
 let value;try{value=decodeURIComponent(location.hash.slice(1));}catch{return;}
 const match=/^(clean|attacked)-(event:.+)$/.exec(value);if(match){const a=match[1]==='clean'?0:1;const row=findRow(a,match[2]);if(row){$('event-filter').value='all';selectRow(row.index,true);$('event-comparison').scrollIntoView({block:'nearest'});}}
}
$('event-filter').addEventListener('change',()=>drawGraph(true));$('event-search').addEventListener('input',()=>drawGraph());
$('overview-source').addEventListener('change',drawOverview);
$('jump-divergence').addEventListener('click',()=>{$('event-filter').value='key';$('event-search').value='';selectRow(data.first_security_row,true);});
document.querySelectorAll('[data-tab]').forEach(button=>{button.addEventListener('click',()=>selectTab(button.dataset.tab));button.addEventListener('keydown',e=>{if(['ArrowLeft','ArrowRight'].includes(e.key)){e.preventDefault();const tabs=['compare','sources','evidence'],i=tabs.indexOf(currentTab);selectTab(tabs[(i+(e.key==='ArrowRight'?1:2))%3]);$('tab-'+currentTab).focus();}});});
window.addEventListener('hashchange',openHash);
buildHeader();setupOverviewSources();drawOverview();if(data.rows.length){selectRow(defaultRow,true);openHash();requestAnimationFrame(()=>drawGraph(true));}
