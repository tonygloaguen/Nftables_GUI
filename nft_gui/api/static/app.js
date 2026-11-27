import {clone, parseJsonSafely, actionNames, kindNames, buildRule, decodeRule, valueText, ipValue, portValue, integer} from './model.js';
import {filterTemplates, templateValues} from './templates.js';

const $=selector=>document.querySelector(selector);
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const tableKey=t=>JSON.stringify([t.family,t.name]);
const DRAFT_KEY='nft-gui-draft-v1';
const S={ir:{objects:[],raw_nft:null},source:'',activeSource:'',view:'rules',table:null,chain:null,revision:0,validRevision:-1,dirty:false,connected:false,health:null,token:'',busy:false,undo:[],tx:null,persisted:true,lastVisual:null};
let submitModal=null,modalEpoch=0,toastTimer,previewTimer,codeHistoryTime=0,polling=false,previewVersion=0;
const T={catalog:null,loading:null,query:'',category:'all',selected:null,previewVersion:0,timer:null};
const activeStatuses=new Set(['prepared','applying','pending','rollback_failed']);

function friendly(error) {
  if(error instanceof TypeError) return 'Connexion impossible au serveur. Vérifiez qu’il est démarré, puis réessayez.';
  return error.message||String(error);
}
async function api(path,body,options={}) {
  const headers={};
  if(S.token) headers.Authorization='Bearer '+S.token;
  if(body!==undefined) headers['Content-Type']='application/json';
  const response=await fetch(path,{method:body===undefined?'GET':'POST',headers,body:body===undefined?undefined:JSON.stringify(body),cache:'no-store'});
  if(!response.ok) {
    let result;try{result=await response.json();}catch{result={detail:response.statusText};}
    const detail=result.detail;
    if(response.status===401) {S.connected=false;updateChrome();throw Error('Authentification requise. Connectez-vous avec le jeton du serveur.');}
    if(Array.isArray(detail)) throw Error(detail.map(x=>`${x.loc?.slice(1).join('.')||'Configuration'} : ${x.msg}`).join('\n'));
    const messages={validation_failed:'La configuration a été refusée par nftables.',timeout:'La commande a dépassé le délai autorisé.',execution_unavailable:'Le validateur nftables ou son environnement isolé n’est pas disponible.',watchdog_unavailable:'Le surveillant de retour arrière n’a pas pu démarrer. Application annulée.',conflict:'Une transaction attend déjà une confirmation ou un retour arrière.',unsupported_syntax:'Cette construction avancée ne peut pas être convertie automatiquement. Conservez-la dans l’éditeur de code.',unsafe_source:'Le fichier doit être autonome : tables, règles et un unique flush ruleset initial. Les inclusions et macros sont refusées.'};
    const message=typeof detail==='string'?detail:(messages[detail?.code]||detail?.message||'Opération impossible.');
    throw Error(message+(detail?.stderr?'\n\n'+detail.stderr:detail?.message&&messages[detail.code]?'\n'+detail.message:''));
  }
  return options.raw?response:parseJsonSafely(await response.text());
}
function notice(message,info=false) {const node=$('#notice');node.className=info?'info':'';node.innerHTML=esc(message)+'<button class="icon-button" data-action="dismiss-notice" aria-label="Fermer le message">×</button>';node.hidden=false;}
function toast(message) {clearTimeout(toastTimer);$('#toast').textContent=message;$('#toast').hidden=false;toastTimer=setTimeout(()=>$('#toast').hidden=true,4200);}
function saveDraft() {
  try{localStorage.setItem(DRAFT_KEY,JSON.stringify({ir:S.ir,source:S.source,base:S.activeSource,savedAt:new Date().toISOString(),dirty:S.dirty}));S.persisted=true;}
  catch{S.persisted=false;}
}
function normalizeSelection() {
  const tables=S.ir.objects?.filter(o=>o.kind==='table')||[];
  const selected=tables.find(t=>tableKey(t)===S.table)||tables[0];
  S.table=selected?tableKey(selected):null;
  const chains=selected?S.ir.objects.filter(o=>o.kind==='chain'&&o.family===selected.family&&o.table===selected.name):[];
  if(!chains.some(c=>c.name===S.chain)) S.chain=chains[0]?.name||null;
}
function table() {return S.ir.objects.find(o=>o.kind==='table'&&tableKey(o)===S.table);}
function chain() {const t=table();return t?S.ir.objects.find(o=>o.kind==='chain'&&o.family===t.family&&o.table===t.name&&o.name===S.chain):null;}
function pushUndo() {S.undo.push(clone(S.ir));if(S.undo.length>30)S.undo.shift();}
function changed(next,record=true) {
  if(record)pushUndo();S.ir=clone(next);S.revision++;S.validRevision=-1;S.dirty=true;
  S.source=S.ir.raw_nft??'';normalizeSelection();saveDraft();render();
}
function payload() {return S.ir.raw_nft!==null&&S.ir.raw_nft!==undefined?{source:S.ir.raw_nft}:{ruleset:S.ir};}
async function source() {
  if(S.ir.raw_nft!==null&&S.ir.raw_nft!==undefined)return S.ir.raw_nft;
  const rev=S.revision;const result=await api('/generate',S.ir);
  if(rev===S.revision){S.source=result.source;S.lastVisual={ir:clone(S.ir),source:result.source};saveDraft();}
  return result.source;
}
function updateChrome() {
  const opaque=S.ir.raw_nft!==null&&S.ir.raw_nft!==undefined;
  for(const [kind,node] of [['table','#table-count'],['chain','#chain-count'],['rule','#rule-count']])$(node).textContent=opaque?'—':S.ir.objects.filter(o=>o.kind===kind).length;
  $('#draft-state').textContent=!S.connected?'Non connecté':S.busy?'Opération en cours':S.validRevision===S.revision?'Configuration vérifiée':S.dirty?'Modifications à vérifier':'État chargé';
  $('#save-state').textContent=S.persisted?'Brouillon enregistré dans ce navigateur':'Sauvegarde locale indisponible';
  $('#draft-note').textContent=S.health?.live?'Mode réel · les changements nécessitent une confirmation.':'Mode fichier · les changements restent dans le bac à sable.';
  const pending=S.tx&&activeStatuses.has(S.tx.status);
  $('#apply-button').disabled=!S.connected||S.busy||pending||S.validRevision!==S.revision;
  $('#validate-button').disabled=!S.connected||S.busy||pending;
  $('#undo-button').disabled=!S.undo.length||S.busy||pending;
  document.body.classList.toggle('busy',S.busy);
  document.querySelectorAll('[data-view]').forEach(n=>{n.classList.toggle('active',n.dataset.view===S.view);if(n.dataset.view===S.view)n.setAttribute('aria-current','page');else n.removeAttribute('aria-current');});
  if(S.health){$('#mode-label').textContent=S.health.live?'Mode réel':'Bac à sable';$('#mode-label').classList.toggle('live',S.health.live);$('#mode-description').textContent=S.health.live?'Les opérations peuvent modifier le pare-feu hôte.':'Créez et vérifiez vos règles dans un fichier local.';}
  $('#logout').hidden=!S.token;
}
function field(name,label,value='',placeholder='',options={}) {
  return `<label class="field ${options.full?'full':''}"><span>${esc(label)}</span><input name="${esc(name)}" value="${esc(value)}" placeholder="${esc(placeholder)}" type="${options.type||'text'}" ${options.required?'required':''} ${options.min!==undefined?`min="${options.min}"`:''} ${options.max!==undefined?`max="${options.max}"`:''} ${options.autocomplete?'autocomplete="'+options.autocomplete+'"':''}>${options.help?`<small>${esc(options.help)}</small>`:''}</label>`;
}
function select(name,label,values,current,full=false) {return `<label class="field ${full?'full':''}"><span>${esc(label)}</span><select name="${esc(name)}">${values.map(v=>{const [key,label]=Array.isArray(v)?v:[v,v];return `<option value="${esc(key)}" ${String(key)===String(current)?'selected':''}>${esc(label)}</option>`;}).join('')}</select></label>`;}
function textarea(name,label,value='',help='') {return `<label class="field full"><span>${esc(label)}</span><textarea name="${esc(name)}" spellcheck="false" class="code">${esc(value)}</textarea>${help?`<small>${esc(help)}</small>`:''}</label>`;}
function check(name,label,checked=false) {return `<label class="check"><input type="checkbox" name="${esc(name)}" ${checked?'checked':''}>${esc(label)}</label>`;}
function showDialog(title,body,submitText,handler,eyebrow='BROUILLON') {
  T.selected=null;T.previewVersion++;clearTimeout(T.timer);$('#dialog').classList.remove('template-dialog');
  modalEpoch++;submitModal=handler;$('#dialog-title').textContent=title;$('#dialog-eyebrow').textContent=eyebrow;$('#dialog-body').innerHTML=body;$('#dialog-submit').textContent=submitText;$('#dialog-submit').disabled=false;$('#dialog-error').hidden=true;
  if(!$('#dialog').open)$('#dialog').showModal();
  setTimeout(()=>$('#dialog-body').querySelector('input,select,textarea,button')?.focus(),30);
}
function confirmDialog(title,message,handler,submit='Confirmer') {showDialog(title,`<p>${esc(message)}</p>`,submit,handler);}
$('#dialog-form').addEventListener('submit',async e=>{
  e.preventDefault();const epoch=modalEpoch;const values=Object.fromEntries(new FormData(e.currentTarget));$('#dialog-submit').disabled=true;$('#dialog-error').hidden=true;
  try{await submitModal?.(values);if(epoch===modalEpoch)$('#dialog').close();}
  catch(error){$('#dialog-error').textContent=friendly(error);$('#dialog-error').hidden=false;}
  finally{if(epoch===modalEpoch)$('#dialog-submit').disabled=false;}
});
function ruleItems(c=chain()) {return c?S.ir.objects.map((o,i)=>({o,i})).filter(({o})=>o.kind==='rule'&&o.family===c.family&&o.table===c.table&&o.chain===c.name):[];}
function ruleRow({o,i},order,total) {
  const v=decodeRule(o);const action=v.advanced?'advanced':v.action;
  return `<tr><td class="rule-order">${String(order+1).padStart(2,'0')}</td><td><span class="tag ${esc(action)}">${esc(actionNames[action]||action)}</span><span class="subtext">${esc(o.comment||'Sans commentaire')}</span></td><td>${v.advanced?'Avancée':esc(v.protocol==='any'?'Tous':v.protocol.toUpperCase())}</td><td><span class="rule-label">${esc(v.source||'Toutes')}</span><span class="subtext">${esc(v.iif?'Entrée : '+v.iif:'Toutes interfaces')}</span></td><td><span class="rule-label">${esc(v.destination||'Toutes')}</span><span class="subtext">${esc(v.dport?'Ports '+v.dport:v.oif?'Sortie : '+v.oif:'Tous ports')}</span></td><td><div class="row-tools"><button data-action="move-rule" data-index="${i}" data-direction="-1" ${order===0?'disabled':''} title="Monter la règle" aria-label="Monter la règle">↑</button><button data-action="move-rule" data-index="${i}" data-direction="1" ${order===total-1?'disabled':''} title="Descendre la règle" aria-label="Descendre la règle">↓</button><button data-action="edit-rule" data-index="${i}" title="Modifier la règle" aria-label="Modifier la règle">✎</button><button data-action="copy-rule" data-index="${i}" title="Dupliquer la règle" aria-label="Dupliquer la règle">⧉</button><button data-action="delete-rule" data-index="${i}" title="Supprimer la règle" aria-label="Supprimer la règle">×</button></div></td></tr>`;
}
function rulesView() {
  const title=`<div class="page-title"><div><h1>Construire vos règles</h1><p>Un formulaire pour définir le trafic autorisé, bloqué ou traduit.</p></div><div class="actions"><button data-action="template">Partir d’un modèle</button><button class="primary" data-action="add-rule" ${!chain()?'disabled':''}>+ Ajouter une règle</button></div></div>`;
  if(S.ir.raw_nft!==null&&S.ir.raw_nft!==undefined) return title+`<div class="card empty"><div class="empty-symbol">⌘</div><h2>Cette configuration est conservée en mode code</h2><p>Elle contient du texte ou des constructions que l’éditeur visuel ne sait pas convertir sans perte. Vous pouvez la modifier, la vérifier et l’appliquer dans l’éditeur de code.</p><div class="actions"><button data-view="code" class="primary">Ouvrir l’éditeur de code</button><button data-action="new">Créer un nouveau brouillon</button></div></div>`;
  const t=table(),c=chain(),tables=S.ir.objects.filter(o=>o.kind==='table');
  if(!t) return title+`<div class="card empty"><div class="empty-symbol">▤</div><h2>Votre première configuration commence ici</h2><p>Choisissez un modèle expliqué pour votre usage ou créez votre première table. Vous pourrez ajuster chaque règle avant de l’appliquer.</p><div class="actions"><button class="primary" data-action="template">Choisir un modèle</button><button data-action="add-table">Créer une table</button></div></div>`;
  const chains=S.ir.objects.filter(o=>o.kind==='chain'&&o.family===t.family&&o.table===t.name),rules=ruleItems();
  return title+`<div class="rules-layout"><section class="card structure"><div class="card-body"><label for="table-select">Table active</label><select id="table-select">${tables.map(x=>`<option value="${esc(tableKey(x))}" ${tableKey(x)===S.table?'selected':''}>${esc(x.name)} · ${esc(x.family)}</option>`).join('')}</select><div class="table-tools"><button data-action="edit-table">Modifier</button><button data-action="delete-table">Supprimer</button></div></div><div>${chains.map(x=>`<button class="chain-button ${c?.name===x.name?'selected':''}" data-chain="${esc(x.name)}"><strong>${esc(x.name)}</strong><span>${esc(x.hook||'Chaîne régulière')} · ${ruleItems(x).length} règle(s)</span></button>`).join('')}</div><div class="structure-footer"><button data-action="add-chain">+ Nouvelle chaîne</button><button class="quiet" data-action="add-table">+ Nouvelle table</button></div></section><div>${c?`<div class="chain-info"><strong>${esc(c.name)}</strong><span class="tag">${esc(c.hook||'Régulière')}</span>${c.policy?`<span>Politique par défaut : <strong>${c.policy==='drop'?'bloquer':'autoriser'}</strong></span>`:''}<button class="small quiet" data-action="edit-chain">Configurer</button><button class="small quiet" data-action="delete-chain">Supprimer</button></div><section class="card">${rules.length?`<div class="rule-list"><table class="rules-table"><thead><tr><th>ORDRE</th><th>DÉCISION</th><th>PROTOCOLE</th><th>SOURCE</th><th>DESTINATION</th><th><span class="subtext">ACTIONS</span></th></tr></thead><tbody>${rules.map((r,n)=>ruleRow(r,n,rules.length)).join('')}</tbody></table></div>`:`<div class="empty"><h2>Aucune règle dans cette chaîne</h2><p>${c.policy==='drop'?'La politique par défaut bloquera le trafic qui atteint cette chaîne.':'Ajoutez une règle pour préciser le traitement du trafic.'}</p><button data-action="add-rule" class="primary">Ajouter la première règle</button></div>`}<div class="hint">Les règles sont évaluées de haut en bas. Une décision terminale arrête l’évaluation de la chaîne.</div></section>`:`<div class="card empty"><h2>Ajoutez une chaîne</h2><p>Une chaîne détermine où vos règles agissent : trafic entrant, sortant ou transféré.</p><button data-action="add-chain" class="primary">Créer une chaîne</button></div>`}<section class="card preview"><div class="card-header"><strong>Aperçu nftables</strong><button class="small quiet" data-view="code">Ouvrir le code complet</button></div><pre id="source-preview">Génération de l’aperçu…</pre></section></div></div>`;
}
function objectsView() {
  const objects=S.ir.objects.map((o,i)=>({o,i})).filter(({o})=>kindNames[o.kind]);
  return `<div class="page-title"><div><h1>Ensembles & objets</h1><p>Réutilisez des adresses, des ports, des compteurs et des quotas.</p></div><button class="primary" data-action="add-object" ${!table()?'disabled':''}>+ Ajouter un objet</button></div>${!objects.length?`<div class="card empty"><h2>Des objets pour simplifier vos règles</h2><p>Un ensemble regroupe plusieurs adresses ou ports. Dans une règle, référencez un ensemble d’adresses avec @son_nom. Commencez par créer une table si nécessaire.</p><button data-action="add-object" ${!table()?'disabled':''}>Créer un ensemble</button></div>`:`<div class="object-grid">${objects.map(({o,i})=>`<article class="card"><div class="card-body"><div class="object-heading"><h3>${esc(o.name)}</h3><span class="tag">${esc(kindNames[o.kind])}</span></div><span class="subtext">${esc(o.family)} / ${esc(o.table)}${o.type?' · '+esc(Array.isArray(o.type)?o.type.join(' . '):o.type):''}</span><pre>${esc(o.elem?o.kind==='map'?JSON.stringify(o.elem,null,2):o.elem.map(valueText).join('\n'):o.kind==='counter'?`${o.packets||0} paquets · ${o.bytes||0} octets`:`${o.used||0} / ${o.bytes} octets`)}</pre><div class="actions"><button class="small" data-action="edit-object" data-index="${i}">Modifier</button><button class="small quiet" data-action="delete-object" data-index="${i}">Supprimer</button></div></div></article>`).join('')}</div>`}`;
}
function codeView() {return `<div class="page-title"><div><h1>Éditeur de code</h1><p>La source complète reste disponible pour les configurations avancées.</p></div><div class="actions"><button data-action="to-visual">Convertir vers le visuel</button><button data-action="copy-code">Copier le code</button></div></div><div class="info-panel">Les modifications de code invalident la vérification précédente. Vérifiez à nouveau avant d’appliquer.</div><div class="card"><div class="editor-toolbar"><strong>ruleset.nft</strong><span class="code-meta">Syntaxe nftables · UTF-8</span></div><textarea id="code-editor" class="code-editor" aria-label="Code nftables" spellcheck="false">${esc(S.ir.raw_nft??S.source)}</textarea></div>`;}
function helpView(){return `<div class="page-title"><div><h1>Du brouillon au pare-feu</h1><p>Quatre étapes, avec un retour arrière prévu dès le départ.</p></div></div><div class="steps"><article class="card card-body"><h2>Organiser</h2><p>Une table regroupe votre configuration. Une chaîne choisit le trafic traité : <strong>input</strong> pour ce qui arrive sur la machine, <strong>output</strong> pour ce qui en sort, <strong>forward</strong> pour ce qui la traverse.</p><button data-action="template">Choisir un modèle</button></article><article class="card card-body"><h2>Définir les règles</h2><p>Choisissez une action et des critères : protocole, adresses, ports ou interfaces. Laissez un critère vide pour accepter toutes ses valeurs. Réordonnez les règles selon leur priorité.</p><button data-view="rules">Ouvrir les règles</button></article><article class="card card-body"><h2>Vérifier</h2><p>Le bouton de vérification transmet la configuration à nftables sans l’appliquer. Les erreurs sont affichées avec leurs lignes et colonnes lorsqu’elles sont disponibles.</p></article><article class="card card-body"><h2>Appliquer et confirmer</h2><p>Une sauvegarde précède chaque application. Vérifiez votre connexion, puis confirmez avant la fin du compte à rebours. Sans confirmation, le serveur tente de restaurer l’état précédent.</p></article></div><div class="info-panel section-spacer" hidden></div><p class="help-note">Le mode fichier utilise un espace réseau isolé pour la vérification. S’il n’est pas autorisé sur votre système, la validation est bloquée et une erreur explicite s’affiche. Les modifications remplacent l’ensemble du ruleset, y compris en mode réel.</p><div class="actions"><button data-action="new">Nouveau brouillon vide</button><a href="/docs" target="_blank" rel="noopener">Documentation de l’API</a></div>`;}
function render() {
  updateChrome();if(!S.connected){$('#view').innerHTML='<div class="card empty"><h1>Connexion au serveur</h1><p>Connectez-vous pour charger votre configuration.</p><button class="primary" data-action="connect">Se connecter / réessayer</button></div>';return;}
  if(S.view==='rules'){$('#view').innerHTML=rulesView();refreshPreview();}
  if(S.view==='objects')$('#view').innerHTML=objectsView();
  if(S.view==='code'){$('#view').innerHTML=codeView();if(S.ir.raw_nft==null&&!S.source)source().then(v=>{if(S.view==='code')$('#code-editor').value=v;}).catch(e=>notice(friendly(e)));}
  if(S.view==='help')$('#view').innerHTML=helpView();
  if(S.view==='templates')renderTemplates();
  if(['history','audit'].includes(S.view))renderHistory();
}
async function refreshPreview() {
  const node=$('#source-preview');if(!node)return;const revision=S.revision;
  try{const text=await source();if(node.isConnected&&revision===S.revision)node.textContent=text;}
  catch(error){if(node.isConnected)node.textContent=friendly(error);}
}
async function renderHistory() {
  const view=S.view;$('#view').innerHTML=`<div class="page-title"><div><h1>${view==='history'?'Sauvegardes automatiques':'Journal d’activité'}</h1><p>${view==='history'?'Chaque application conserve la configuration précédente.':'Les opérations et leur résultat, du plus récent au plus ancien.'}</p></div><button data-action="refresh-history">Actualiser</button></div><div class="card" id="history-content"><div class="empty">Chargement…</div></div>`;
  try{
    const data=await api(view==='history'?'/snapshots':'/audit');if(S.view!==view)return;
    if(view==='history')$('#history-content').innerHTML=data.snapshots.length?data.snapshots.map(x=>`<div class="history-row"><div><strong>${esc(new Date(x.created_at).toLocaleString('fr-FR'))}</strong><p>${Math.ceil(x.size/1024)} Ko · configuration précédente</p></div><div class="actions"><button data-action="inspect-snapshot" data-id="${esc(x.id)}">Consulter</button><button data-action="restore-snapshot" data-id="${esc(x.id)}">Restaurer…</button></div></div>`).join(''):'<div class="empty"><h2>Aucune sauvegarde pour le moment</h2><p>La première sera créée avant votre première application.</p></div>';
    else $('#history-content').innerHTML=data.entries.length?`<div class="scroll"><table class="log"><thead><tr><th>DATE</th><th>OPÉRATION</th><th>RÉSULTAT</th><th>DÉTAIL / EMPREINTE</th></tr></thead><tbody>${data.entries.map(x=>`<tr><td>${esc(new Date(x.timestamp).toLocaleString('fr-FR'))}</td><td>${esc({'read':'Lecture','dry-run':'Vérification',apply:'Application',confirm:'Confirmation',rollback:'Retour arrière',export:'Export'}[x.action]||x.action)}</td><td><span class="tag ${x.status==='error'?'drop':'accept'}">${esc(x.status)}</span></td><td>${x.detail?esc(x.detail):`<code>${esc(x.ruleset_hash?.slice(0,20)||'—')}</code>`}</td></tr>`).join('')}</tbody></table></div>`:'<div class="empty">Aucune opération enregistrée.</div>';
  }catch(error){if(S.view===view)$('#history-content').textContent=friendly(error);}
}

function tableDialog(edit=false) {
  const current=edit?table():null;
  showDialog(edit?'Configurer la table':'Créer une table',`<p class="modal-subtitle">Une table regroupe vos chaînes et vos objets. La famille inet convient à un pare-feu IPv4 et IPv6.</p><div class="form-grid">${field('name','Nom',current?.name||'','filter',{required:true})}${select('family','Famille',[['inet','inet · IPv4 et IPv6'],['ip','ip · IPv4'],['ip6','ip6 · IPv6'],['bridge','bridge · pont réseau'],['netdev','netdev · interface'],['arp','arp']],current?.family||'inet')}${field('comment','Commentaire',current?.comment||'','Filtrage principal',{full:true})}</div>`,edit?'Enregistrer dans le brouillon':'Créer la table',async v=>{
    if(!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(v.name))throw Error('Utilisez un nom simple : lettres, chiffres, tirets ou underscores.');
    if(S.ir.objects.some(o=>o.kind==='table'&&o!==current&&o.name===v.name&&o.family===v.family))throw Error('Cette table existe déjà.');
    if(current&&(v.name!==current.name||v.family!==current.family))throw Error('Le nom et la famille d’une table existante sont conservés. Créez une nouvelle table pour les changer.');
    const next=clone(S.ir),obj={...(current||{}),kind:'table',family:v.family,name:v.name,comment:v.comment||null};
    if(current)next.objects[S.ir.objects.indexOf(current)]=obj;else next.objects.push(obj);
    S.table=tableKey(obj);changed(next);
  });
}
function chainDialog(edit=false) {
  const t=table(),current=edit?chain():null;if(!t)throw Error('Créez une table avant d’ajouter une chaîne.');
  showDialog(edit?'Configurer la chaîne':'Créer une chaîne',`<p class="modal-subtitle">Choisissez le point de passage du trafic. Une chaîne régulière est appelée par une règle de saut.</p><div class="form-grid">${field('name','Nom',current?.name||'','input',{required:true})}${select('hook','Trafic traité',[['input','input · vers cette machine'],['output','output · depuis cette machine'],['forward','forward · à travers cette machine'],['prerouting','prerouting · avant routage'],['postrouting','postrouting · après routage'],['ingress','ingress · entrée interface'],['egress','egress · sortie interface'],['','Chaîne régulière (sans hook)']],current?current.hook||'':'input')}${select('type','Type',[['filter','Filtrage'],['nat','Traduction NAT'],['route','Routage']],current?.type||'filter')}${select('policy','Politique par défaut',[['accept','Autoriser le trafic non traité'],['drop','Bloquer le trafic non traité']],current?.policy||'accept')}${field('prio','Priorité',current?.prio??0,'0')}${field('dev','Interface (netdev)',current?.dev||'','eth0')}${field('comment','Commentaire',current?.comment||'','',{full:true})}</div>`,edit?'Enregistrer':'Créer la chaîne',async v=>{
    if(!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(v.name))throw Error('Nom de chaîne invalide.');
    if(current&&v.name!==current.name)throw Error('Le nom d’une chaîne existante est conservé pour protéger les références.');
    if(S.ir.objects.some(o=>o.kind==='chain'&&o!==current&&o.family===t.family&&o.table===t.name&&o.name===v.name))throw Error('Cette chaîne existe déjà.');
    const obj={...(current||{}),kind:'chain',family:t.family,table:t.name,name:v.name,comment:v.comment||null,type:v.hook?v.type:null,hook:v.hook||null,prio:v.hook?(/^-?\d+$/.test(v.prio)?+v.prio:v.prio):null,policy:v.hook?v.policy:null,dev:v.hook&&v.dev?v.dev:null};
    const next=clone(S.ir);if(current)next.objects[S.ir.objects.indexOf(current)]=obj;else next.objects.push(obj);
    await api('/generate',next);S.chain=v.name;changed(next);
  });
}
function ruleDialog(index=null) {
  const existing=index!==null?S.ir.objects[index]:null,c=chain();if(!c)throw Error('Créez et sélectionnez une chaîne.');
  const v=existing?decodeRule(existing):{action:'accept',protocol:'tcp',counter:true};
  if(v.advanced){advancedRuleDialog(existing,index);return;}
  const targets=S.ir.objects.filter(o=>o.kind==='chain'&&o.family===c.family&&o.table===c.table&&!o.hook).map(o=>o.name);
  showDialog(existing?'Modifier la règle':'Ajouter une règle',`<p class="modal-subtitle">Chaîne <strong>${esc(c.name)}</strong> · table ${esc(c.table)} (${esc(c.family)}). Les champs vides correspondent à toutes les valeurs.</p><div class="form-grid">${select('action','Décision',Object.entries(actionNames).filter(([k])=>k!=='advanced'),v.action)}${select('protocol','Protocole',[['any','Tous les protocoles'],['tcp','TCP'],['udp','UDP'],['icmp','ICMP (IPv4)'],['ipv6-icmp','ICMPv6']],v.protocol)}${field('source','Adresse source',v.source||'','192.168.1.0/24 ou @clients',{help:'Adresse, réseau, liste séparée par des virgules ou ensemble nommé.'})}${field('destination','Adresse destination',v.destination||'','Toutes les destinations')}${field('sport','Port source',v.sport||'','Tous les ports')}${field('dport','Port destination',v.dport||'','22, 80, 443 ou 8000-8010')}${field('iif','Interface d’entrée',v.iif||'','Toutes (ex. enp3s0)')}${field('oif','Interface de sortie',v.oif||'','Toutes (ex. enp4s0)')}${field('states','États de connexion',v.states||'','established, related',{full:true})}<div class="field full" id="target-fields">${select('target','Chaîne cible',[['','Sélectionner une chaîne régulière'],...targets],v.target||'')}</div><div class="field full" id="nat-fields"><div class="form-grid">${field('natAddress','Adresse de traduction',v.natAddress||'','192.168.1.10')}${field('natPort','Port traduit (facultatif)',v.natPort||'','8080')}</div><small>Utilisez une chaîne de type NAT avec un hook compatible.</small></div><div class="form-section">Suivi et lisibilité</div>${check('counter','Compter les paquets et les octets',v.counter)}${check('log','Journaliser les paquets correspondants',v.log)}${field('logprefix','Préfixe de journalisation',v.logprefix||'','nft-gui: ',{full:true})}${field('comment','Commentaire',v.comment||'','Autoriser l’accès au serveur web',{full:true})}<div class="field full"><span>Aperçu de la règle</span><pre class="form-preview" id="rule-preview">Renseignez les critères de votre règle.</pre></div></div>`,existing?'Enregistrer la règle':'Ajouter au brouillon',async values=>{
    const obj=buildRule(values,c,S.ir.objects,existing),next=clone(S.ir);
    if(index!==null)next.objects[index]=obj;else next.objects.push(obj);
    await api('/generate',next);changed(next);
  });
  $('#dialog-form').dataset.ruleIndex=index===null?'new':String(index);updateRuleFields();previewRule();
}
function updateRuleFields(){const action=$('#dialog-form [name="action"]')?.value;if(!action)return;$('#target-fields').hidden=!['jump','goto'].includes(action);$('#nat-fields').hidden=!['dnat','snat'].includes(action);}
async function previewRule(){
  const node=$('#rule-preview');if(!node)return;const epoch=modalEpoch,version=++previewVersion;
  try{const values=Object.fromEntries(new FormData($('#dialog-form'))),index=$('#dialog-form').dataset.ruleIndex,old=index==='new'?null:S.ir.objects[+index],c=chain(),obj=buildRule(values,c,S.ir.objects,old),next=clone(S.ir);
    const pos=index==='new'?next.objects.length:+index;if(index==='new')next.objects.push(obj);else next.objects[pos]=obj;
    const result=await api('/generate',next);const prefix=`add rule ${c.family} ${JSON.stringify(c.table)} ${JSON.stringify(c.name)} `;
    const ordinal=next.objects.slice(0,pos).filter(o=>o.kind==='rule'&&o.family===c.family&&o.table===c.table&&o.chain===c.name).length;
    if(epoch===modalEpoch&&version===previewVersion&&node.isConnected)node.textContent=result.source.split('\n').filter(l=>l.startsWith(prefix))[ordinal]?.slice(prefix.length)||'Aperçu disponible après vérification.';
  }catch(error){if(epoch===modalEpoch&&version===previewVersion&&node.isConnected)node.textContent=friendly(error);}
}
function advancedRuleDialog(existing,index){
  const raw=existing.raw_nft||(existing.expr||[]).map(e=>e.raw_nft||'').filter(Boolean).join(' ');
  showDialog('Modifier une règle avancée',`<p class="modal-subtitle">Les expressions non reconnues sont conservées. Pour les appliquer en syntaxe nftables, renseignez une source exacte, ou éditez les expressions structurées.</p><div class="form-grid">${textarea('raw','Source de la règle .nft (facultative)',raw,'Une seule règle, sans préfixe add rule ni nom de chaîne. Cette source devient prioritaire si elle est renseignée.')}${textarea('expressions','Expressions structurées (JSON)',JSON.stringify(existing.expr,null,2))}${field('comment','Commentaire',existing.comment||'','',{full:true})}</div>`,'Enregistrer dans le brouillon',async v=>{
    const next=clone(S.ir);next.objects[index]={...next.objects[index],raw_nft:v.raw.trim()||null,expr:parseJsonSafely(v.expressions),comment:v.comment||null};
    const normalized=await api('/parse/ir',next);changed(normalized);
  });
}
function objectDialog(index=null){
  const existing=index!==null?S.ir.objects[index]:null,t=existing?{family:existing.family,name:existing.table}:table();if(!t)throw Error('Créez une table avant d’ajouter un objet.');
  if(existing&&(existing.raw_nft||Array.isArray(existing.type)||Array.isArray(existing.map)||Object.keys(existing.extra_fields||{}).length))throw Error('Cet objet contient des attributs avancés. Conservez-le via un export JSON ou modifiez la configuration en mode code.');
  showDialog(existing?'Modifier l’objet':'Créer un objet',`<p class="modal-subtitle">Table ${esc(t.name)} · ${esc(t.family)}. Les ensembles sont réutilisables dans vos règles.</p><div class="form-grid">${select('kind','Objet',Object.entries(kindNames),existing?.kind||'set')}${field('name','Nom',existing?.name||'','clients',{required:true})}<div class="field full" id="set-fields"><div class="form-grid">${select('type','Type de clé',[['ipv4_addr','Adresses IPv4'],['ipv6_addr','Adresses IPv6'],['inet_service','Ports réseau'],['mark','Marques numériques']],existing?.type||'ipv4_addr')}${select('map','Type de valeur (maps)',[['verdict','Verdicts (accept, drop, jump…)'],['ipv4_addr','Adresse IPv4'],['ipv6_addr','Adresse IPv6'],['mark','Nombre']],existing?.map||'verdict')}${textarea('elements','Éléments',existing?.kind==='map'?JSON.stringify(existing.elem||[],null,2):(existing?.elem||[]).map(valueText).join('\n'),'Ensemble : une adresse, un réseau ou un port par ligne. Map : tableau JSON de paires, ex. [[80,{"accept":null}],[22,{"drop":null}]].')}${field('timeout','Durée de vie en secondes (facultative)',existing?.timeout??'','Permanent',{type:'number',min:0})}</div></div><div class="field full" id="counter-fields"><div class="form-grid">${field('packets','Paquets',existing?.packets||0,'0',{type:'number',min:0})}${field('bytes','Octets / seuil du quota',existing?.bytes||0,'0',{type:'number',min:0})}${field('used','Octets déjà consommés (quota)',existing?.used||0,'0',{type:'number',min:0})}${check('inv','Quota dépassé (over)',existing?.inv||false)}</div></div>${field('comment','Commentaire',existing?.comment||'','',{full:true})}</div>`,'Enregistrer l’objet',async v=>{
    if(!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(v.name))throw Error('Nom d’objet invalide.');
    if(existing&&(v.kind!==existing.kind||v.name!==existing.name))throw Error('Le nom et le type d’un objet existant sont conservés.');
    if(S.ir.objects.some(o=>o!==existing&&o.family===t.family&&o.table===t.name&&o.name===v.name&&(['set','map'].includes(v.kind)?['set','map'].includes(o.kind):o.kind===v.kind)))throw Error('Un objet avec ce nom existe déjà.');
    const obj={...(existing||{}),kind:v.kind,family:t.family,table:t.name,name:v.name,comment:v.comment||null};
    if(['set','map'].includes(v.kind)){
      obj.type=v.type;obj.elem=v.kind==='map'?parseJsonSafely(v.elements||'[]'):v.elements.split(/\n/).map(s=>s.trim()).filter(Boolean).map(s=>{
        if(['ipv4_addr','ipv6_addr'].includes(v.type)){const ip=ipValue(s);if(ip.family!==(v.type==='ipv4_addr'?'ip':'ip6'))throw Error('La famille d’un élément ne correspond pas au type choisi.');return ip.value;}
        return v.type==='inet_service'?portValue(s):integer(s,'Marque');
      });
      const flags=new Set(existing?.flags||[]);
      if(JSON.stringify(obj.elem).includes('"prefix"')||JSON.stringify(obj.elem).includes('"range"'))flags.add('interval');
      obj.timeout=v.timeout===''?null:integer(v.timeout,'Durée de vie');if(obj.timeout!==null)flags.add('timeout');
      obj.flags=[...flags];
      if(v.kind==='map')obj.map=v.map;
    }else{obj.bytes=integer(v.bytes,'Octets');if(v.kind==='counter')obj.packets=integer(v.packets,'Paquets');else{obj.used=integer(v.used,'Octets consommés');obj.inv=!!v.inv;}}
    const next=clone(S.ir);if(index!==null)next.objects[index]=obj;else next.objects.push(obj);await api('/generate',next);changed(next);
  });
  updateObjectFields();
}
function updateObjectFields(){const kind=$('#dialog-form [name="kind"]')?.value;if(!kind)return;$('#set-fields').hidden=!['set','map'].includes(kind);$('#counter-fields').hidden=['set','map'].includes(kind);}
async function loadTemplates(){
  if(T.catalog)return T.catalog;
  if(!T.loading)T.loading=api('/templates').then(result=>{T.catalog=result;return result;}).finally(()=>T.loading=null);
  return T.loading;
}
function templateCardsWithQuery(query){T.query=query;templateCards();}
function templateCards(){
  const items=filterTemplates(T.catalog.templates,T.query,T.category);
  $('#template-count').textContent=`${items.length} modèle${items.length>1?'s':''} disponible${items.length>1?'s':''}`;
  $('#template-grid').innerHTML=items.length?items.map(t=>`<article class="card template-card"><div class="card-body"><div class="template-tags"><span class="tag">${esc(t.category)}</span><span class="tag ${t.origin==='formation'?'accept':''}">${t.origin==='formation'?'Issu de la formation':'Configuration classique'}</span></div><h2>${esc(t.title)}</h2><p>${esc(t.summary)}</p><button data-action="template-preview" data-id="${esc(t.id)}">Comprendre et personnaliser →</button></div></article>`).join(''):'<div class="card empty"><h2>Aucun modèle trouvé</h2><p>Essayez un service, un protocole ou une autre catégorie.</p></div>';
}
async function renderTemplates(){
  $('#view').innerHTML='<div class="card empty">Chargement des modèles…</div>';
  try{
    const data=await loadTemplates();if(S.view!=='templates')return;
    const categories=[...new Set(data.templates.map(t=>t.category))];
    $('#view').innerHTML=`<div class="page-title"><div><h1>Modèles expliqués</h1><p>Choisissez un usage, comprenez chaque règle et adaptez les paramètres à votre réseau.</p></div></div><div class="info-panel">Les modèles créent un <strong>brouillon complet</strong>. Consultez les prérequis et adaptez les exemples avant de vérifier la configuration. Aucune règle n’est appliquée en choisissant un modèle.</div><div class="template-filters"><label class="field"><span>Rechercher un usage</span><input id="template-search" type="search" value="${esc(T.query)}" placeholder="SSH, DNS, VPN, VLAN, formation…"></label><label class="field"><span>Catégorie</span><select id="template-category"><option value="all">Toutes les catégories</option>${categories.map(c=>`<option ${T.category===c?'selected':''}>${esc(c)}</option>`).join('')}</select></label><span id="template-count" role="status"></span></div><div id="template-grid" class="template-grid"></div>`;
    templateCards();
  }catch(error){if(S.view==='templates')$('#view').innerHTML=`<div class="card empty"><h2>Catalogue indisponible</h2><p>${esc(friendly(error))}</p><button data-action="template">Réessayer</button></div>`;}
}
function templateReference(id){
  const ref=T.catalog.references.find(r=>r.id===id);if(!ref)return '';
  const location=/^https:\/\//.test(ref.location)?`<a href="${esc(ref.location)}" target="_blank" rel="noopener noreferrer">${esc(ref.title)}</a>`:`<strong>${esc(ref.title)}</strong><code class="source-location">${esc(ref.location)}</code>`;
  return `<li>${location}<p>${esc(ref.note)}</p></li>`;
}
async function templateDialog(id){
  const data=await loadTemplates();const template=data.templates.find(t=>t.id===id);
  if(!template)throw Error('Modèle introuvable.');
  const parameters=template.parameters.map(p=>p.kind==='choice'?select(p.key,p.label,p.choices,p.default):field(p.key,p.label,p.default,'',{required:true,help:p.help,type:p.kind==='port'?'number':'text',...(p.kind==='port'?{min:1,max:65535}:{})})).join('');
  showDialog(template.title,`<p class="modal-subtitle">${esc(template.summary)}</p><div class="info-panel">La création remplace le brouillon actuel. Vous pourrez annuler cette modification. L’application au pare-feu nécessite toujours une vérification puis une confirmation séparée.</div><div class="template-setup"><section><h3>Adapter à mon réseau</h3><div id="template-parameters" class="form-grid">${parameters}</div><div class="template-prerequisites"><h3>À préparer</h3><ul>${template.prerequisites.map(x=>`<li>${esc(x)}</li>`).join('')}</ul></div><details class="template-details"><summary>Portée et limites</summary><ul>${template.caveats.map(x=>`<li>${esc(x)}</li>`).join('')}</ul></details><details class="template-details"><summary>Sources et adaptations</summary><ul>${template.sources.map(templateReference).join('')}</ul></details></section><section aria-label="Explication du modèle">${template.excerpts?.length?`<div class="formation-lessons"><h3>Retrouvé dans votre formation</h3>${template.excerpts.map(x=>`<details class="explained-rule"><summary><strong>Règle originale et adaptation</strong></summary><div><pre>${esc(x.code)}</pre><p>${esc(x.explanation)}</p><p><strong>Dans ce modèle :</strong> ${esc(x.adaptation)}</p><small>${esc(data.references.find(r=>r.id===x.source)?.location||'')}</small></div></details>`).join('')}</div>`:''}<div id="template-preview-status" role="status">Préparation de l’aperçu…</div><div id="template-preview"></div></section></div>`,'Créer le brouillon',async values=>{
    const result=await api('/templates/'+encodeURIComponent(template.id)+'/preview',{values:templateValues(template,values)});
    S.view='rules';changed(result.ruleset);toast('Modèle ajouté au brouillon. Adaptez et vérifiez avant d’appliquer.');
  },template.origin==='formation'?'FORMATION · MODÈLE COMMENTÉ':'MODÈLE COMMENTÉ');
  T.selected=template;$('#dialog').classList.add('template-dialog');await previewTemplate();
}
async function previewTemplate(){
  const template=T.selected;if(!template||!$('#template-preview'))return;
  const version=++T.previewVersion,epoch=modalEpoch;
  $('#template-preview-status').textContent='Mise à jour de l’aperçu…';$('#dialog-submit').disabled=true;
  try{
    const values=templateValues(template,Object.fromEntries(new FormData($('#dialog-form'))));
    const result=await api('/templates/'+encodeURIComponent(template.id)+'/preview',{values});
    if(version!==T.previewVersion||epoch!==modalEpoch||!$('#dialog').open)return;
    $('#template-preview-status').textContent=`${result.rules.length} règles expliquées · vérification nftables requise avant application`;
    $('#template-preview').innerHTML=`<div class="template-policies">${result.policies.map(p=>`<div><strong>${esc(p.chain)}</strong><span class="tag ${p.policy==='drop'?'drop':'accept'}">${p.policy==='drop'?'Bloquer par défaut':'Autoriser par défaut'}</span><small>${esc(p.explanation)}</small></div>`).join('')}</div><h3>Comprendre les règles, dans leur ordre</h3>${result.rules.map(r=>`<details class="explained-rule"><summary><span class="tag">${esc(r.table)} / ${esc(r.chain)} · ${r.order}</span><strong>${esc(r.title)}</strong></summary><div><pre>${esc(r.code)}</pre><p>${esc(r.explanation)}</p><dl>${r.parts.map(part=>`<dt><code>${esc(part.code)}</code></dt><dd>${esc(part.explanation)}</dd>`).join('')}</dl></div></details>`).join('')}<details class="template-details"><summary>Voir le script nftables complet</summary><pre class="template-source">${esc(result.source)}</pre></details>`;
    $('#dialog-submit').disabled=false;
  }catch(error){
    if(version!==T.previewVersion||epoch!==modalEpoch)return;
    $('#template-preview-status').textContent=friendly(error);$('#template-preview').innerHTML='';
  }
}

async function validate(){
  S.busy=true;updateChrome();$('#notice').hidden=true;const rev=S.revision;
  try{const result=await api('/validate',payload());if(rev===S.revision){S.validRevision=rev;S.source=result.source;toast('Configuration valide. Vous pouvez maintenant l’appliquer temporairement.');}}
  catch(error){S.validRevision=-1;notice(friendly(error));}
  finally{S.busy=false;updateChrome();}
}
async function applyDialog(){
  if(S.validRevision!==S.revision)throw Error('Vérifiez d’abord la configuration.');
  const code=await source();const rev=S.revision;
  showDialog(S.health.live?'Appliquer au pare-feu réel':'Appliquer au bac à sable',`<p class="modal-subtitle">L’ensemble du ruleset ${S.health.live?'du pare-feu hôte':'du fichier local'} sera remplacé. Une sauvegarde de l’état précédent sera créée.</p><div class="form-grid">${field('seconds','Délai de confirmation (secondes)',S.health.confirmation_seconds,'60',{type:'number',min:15,max:300,full:true})}<div class="info-panel field full">Après application, vérifiez votre accès réseau puis cliquez sur <strong>Confirmer</strong>. Sans confirmation dans le délai choisi, le surveillant tentera de restaurer la sauvegarde.</div><details class="field full"><summary>Relire la configuration à appliquer</summary><pre class="form-preview">${esc(code)}</pre></details></div>`,'Appliquer temporairement',async v=>{
    if(rev!==S.revision)throw Error('Le brouillon a changé. Vérifiez-le à nouveau.');
    S.busy=true;updateChrome();
    try{S.tx=await api('/transactions',{...payload(),confirm_seconds:integer(v.seconds,'Délai',15,300)});S.dirty=false;S.validRevision=-1;S.activeSource=S.source;saveDraft();renderTransaction();if(S.tx.editor_warning)notice(S.tx.editor_warning,true);toast('Configuration temporaire appliquée : confirmez avant expiration.');}
    catch(error){await pollTransaction();throw error;}
    finally{S.busy=false;updateChrome();}
  },S.health.live?'APPLICATION RÉELLE':'BAC À SABLE');
}
function renderTransaction(){
  const node=$('#transaction'),tx=S.tx;
  if(!tx||!activeStatuses.has(tx.status)){node.hidden=true;return;}
  node.hidden=false;node.classList.toggle('failed',tx.status==='rollback_failed');
  const left=Math.max(0,Math.ceil(tx.expires_at-Date.now()/1000));
  const title=tx.status==='rollback_failed'?'Le retour arrière a échoué':left>0?`Confirmation attendue · ${left} s restantes`:'Délai écoulé · restauration en cours';
  node.innerHTML=`<div><strong>${title}</strong><p>${tx.status==='rollback_failed'?esc(tx.error||'Consultez le journal. Le surveillant réessaie.'):'Vérifiez votre connexion avant de confirmer cette configuration.'}</p></div><div class="actions"><button data-action="rollback" ${S.busy?'disabled':''}>Revenir à la sauvegarde</button><button class="primary" data-action="confirm" ${tx.status!=='pending'||left<=0||S.busy?'disabled':''}>Confirmer</button></div>`;
}
async function pollTransaction(){if(!S.connected||polling)return;polling=true;try{const {transaction}=await api('/transactions/pending');const previous=S.tx;S.tx=transaction;if(previous?.id===transaction?.id&&activeStatuses.has(previous.status)&&!activeStatuses.has(transaction.status)){
      if(transaction.status==='rolled_back'){notice('Le serveur a restauré la configuration précédente. Votre brouillon reste disponible.',true);S.dirty=true;S.validRevision=-1;}
      else if(transaction.status==='confirmed')toast('Configuration confirmée.');
      saveDraft();
    }renderTransaction();updateChrome();}catch(error){if(S.tx&&activeStatuses.has(S.tx.status))notice('Suivi de la transaction interrompu. Le surveillant continue côté serveur.\n'+friendly(error));}finally{polling=false;}}
async function finishTransaction(action){if(!S.tx)return;S.busy=true;updateChrome();try{S.tx=await api(`/transactions/${S.tx.id}/${action}`,{});S.validRevision=-1;if(action==='rollback'){S.dirty=true;notice('Configuration précédente restaurée. Le brouillon reste disponible pour correction.',true);}else{S.dirty=false;toast('Configuration confirmée.');}saveDraft();renderTransaction();}finally{S.busy=false;updateChrome();}}
async function loadActive(){const data=await api('/ruleset');S.ir=data.ruleset;S.source=data.source??'';S.activeSource=S.source;S.revision++;S.validRevision=-1;S.dirty=false;S.undo=[];normalizeSelection();if(data.warning)notice(data.warning,true);if(!S.ir.raw_nft)S.lastVisual={ir:clone(S.ir),source:S.source};saveDraft();render();}
async function connect(){
  const session=await api('/session');if(session.authentication_required&&!S.token){loginDialog();render();return;}
  await loadSession();
}
function loginDialog(){showDialog('Se connecter au serveur',`<p class="modal-subtitle">Saisissez le jeton configuré sur ce serveur. Il restera uniquement en mémoire pendant cette session.</p><div class="form-grid">${field('token','Jeton d’accès','','',{type:'password',required:true,full:true,autocomplete:'off'})}</div>`,'Se connecter',async v=>{S.token=v.token.trim();try{await loadSession();}catch(e){S.token='';throw e;}},'AUTHENTIFICATION');}
async function loadSession(){
  S.health=await api('/health');S.connected=true;
  let saved;try{saved=parseJsonSafely(localStorage.getItem(DRAFT_KEY)||'null');}catch{saved=null;}
  const data=await api('/ruleset');S.ir=data.ruleset;S.source=data.source??'';S.activeSource=S.source;S.dirty=false;
  if(saved?.ir&&saved.dirty){try{S.ir=await api('/parse/ir',saved.ir);S.source=saved.source||saved.ir.raw_nft||'';S.dirty=true;notice(saved.base!==S.activeSource?'Votre brouillon a été restauré. L’état actif a changé depuis sa création : relisez-le avant d’appliquer.':'Votre brouillon non appliqué a été restauré.',true);}catch{notice('Le brouillon local n’a pas pu être relu. L’état actif a été chargé.',true);}}
  if(data.warning)notice(data.warning,true);S.revision++;S.validRevision=-1;normalizeSelection();render();await pollTransaction();
}
async function toVisual(){const text=$('#code-editor')?.value??await source();let next;if(S.lastVisual?.source===text)next=S.lastVisual.ir;else next=await api('/parse/text',{source:text});if(next.raw_nft!==null&&next.raw_nft!==undefined)throw Error('Cette source contient des constructions ou commentaires non convertibles sans perte. Elle reste disponible en mode code. Pour continuer visuellement, importez un export IR/JSON ou retrouvez le brouillon avec Annuler.');S.view='rules';changed(next);}
async function importFile(file){if(!file)return;if(file.size>2000000)throw Error('Le fichier dépasse la taille maximale de 2 Mo.');const text=await file.text();let ir;
  if(text.trim().startsWith('{')){const doc=parseJsonSafely(text);ir=doc.nftables?await api('/parse/json',doc):doc.format==='nft-source'?await api('/parse/text',{source:doc.raw_nft}):await api('/parse/ir',doc);}
  else ir=await api('/parse/text',{source:text});
  const adopt=()=>{S.view=ir.raw_nft!=null?'code':'rules';changed(ir);toast('Fichier importé dans le brouillon.');};
  if(S.dirty)confirmDialog('Remplacer le brouillon ?',`Importer ${file.name} remplacera le brouillon actuel. L’état actif ne sera pas modifié.`,adopt,'Importer');else adopt();
}
function exportDialog(){showDialog('Exporter la configuration',`<div class="form-grid">${select('format','Format',[['nft','Script .nft — vérifié avant export'],['ir','Brouillon visuel .json — conserve toutes les données'],['json','JSON nftables — si la conversion est disponible']],'nft',true)}<p class="help-note field full">Pour retrouver les champs visuels et conserver les expressions avancées, choisissez le format brouillon visuel.</p></div>`,'Télécharger',async v=>{
    const response=await api('/export',{...payload(),format:v.format},{raw:true});const blob=await response.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=v.format==='nft'?'ruleset.nft':v.format==='ir'?'ruleset.ir.json':'ruleset.json';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('Export téléchargé.');
  });}
async function inspectSnapshot(id){const data=await api('/snapshots/'+encodeURIComponent(id));showDialog('Configuration sauvegardée',`<pre class="form-preview">${esc(data.source)}</pre>`,'Charger dans le brouillon',async()=>{const ir=await api('/parse/text',{source:data.source});S.view=ir.raw_nft!=null?'code':'rules';changed(ir);});}
function restoreSnapshot(id){showDialog('Restaurer cette sauvegarde ?',`<p>Une nouvelle sauvegarde sera créée avant la restauration. La restauration sera temporaire et devra être confirmée.</p><div class="form-grid">${field('seconds','Délai de confirmation',60,'60',{type:'number',min:15,max:300,full:true})}</div>`,'Restaurer temporairement',async v=>{S.tx=await api(`/snapshots/${encodeURIComponent(id)}/restore`,{confirm_seconds:integer(v.seconds,'Délai',15,300)});try{await loadActive();}finally{renderTransaction();updateChrome();}});}

document.addEventListener('click',async event=>{
  const button=event.target.closest('button');if(!button||button.disabled)return;
  const action=button.dataset.action,view=button.dataset.view,index=button.dataset.index!==undefined?+button.dataset.index:null;
  if(!action&&!view&&button.dataset.chain===undefined)return;
  try{
    if(action==='close-dialog'){$('#dialog').close();return;}if(action==='dismiss-notice'){$('#notice').hidden=true;return;}
    if(action==='connect'){await connect();return;}
    if(!S.connected){loginDialog();return;}
    if(view){S.view=view;render();return;}
    if(button.dataset.chain!==undefined){S.chain=button.dataset.chain;render();return;}
    if(S.busy)return;
    const pending=S.tx&&activeStatuses.has(S.tx.status);
    if(pending&&!['confirm','rollback','refresh-history','inspect-snapshot','export','copy-code'].includes(action))throw Error('Confirmez ou restaurez la transaction en cours avant de modifier le brouillon.');
    if(action==='add-table'||action==='edit-table')tableDialog(action==='edit-table');
    else if(action==='add-chain'||action==='edit-chain')chainDialog(action==='edit-chain');
    else if(action==='add-rule'||action==='edit-rule')ruleDialog(index);
    else if(action==='add-object'||action==='edit-object')objectDialog(index);
    else if(action==='template'){S.view='templates';render();}
    else if(action==='template-preview')await templateDialog(button.dataset.id);
    else if(action==='new')confirmDialog('Nouveau brouillon vide ?', 'Le brouillon actuel sera remplacé. Aucune règle active ne sera modifiée.',()=>{S.view='rules';changed({objects:[],raw_nft:null});},'Créer le brouillon');
    else if(action==='delete-rule'||action==='delete-object')confirmDialog('Supprimer du brouillon ?',action==='delete-rule'?'Cette règle sera retirée du brouillon.':'Cet objet sera retiré. Corrigez aussi ses références éventuelles dans les règles.',()=>{const next=clone(S.ir);next.objects.splice(index,1);changed(next);},'Supprimer');
    else if(action==='copy-rule'){const next=clone(S.ir),copy=clone(next.objects[index]);delete copy.handle;delete copy.source_fields;copy.comment=(copy.comment||'Règle')+' (copie)';next.objects.splice(index+1,0,copy);changed(next);}
    else if(action==='move-rule'){const rules=ruleItems(),position=rules.findIndex(x=>x.i===index),target=rules[position+(+button.dataset.direction)];if(target){const next=clone(S.ir);[next.objects[index],next.objects[target.i]]=[next.objects[target.i],next.objects[index]];changed(next);}}
    else if(action==='delete-table'){const t=table();confirmDialog('Supprimer la table ?',`La table ${t.name}, ses chaînes, ses règles et ses objets seront retirés du brouillon.`,()=>{const next=clone(S.ir);next.objects=next.objects.filter(o=>!((o.kind==='table'&&o.family===t.family&&o.name===t.name)||(o.family===t.family&&o.table===t.name)));changed(next);},'Supprimer la table');}
    else if(action==='delete-chain'){const c=chain();confirmDialog('Supprimer la chaîne ?',`La chaîne ${c.name} et ses règles seront retirées. Vérifiez les éventuelles règles de saut qui la ciblent.`,()=>{const next=clone(S.ir);next.objects=next.objects.filter(o=>!(o.family===c.family&&o.table===c.table&&((o.kind==='chain'&&o.name===c.name)||(o.kind==='rule'&&o.chain===c.name))));changed(next);},'Supprimer la chaîne');}
    else if(action==='reload'){if(S.dirty)confirmDialog('Recharger l’état actif ?', 'Le brouillon non appliqué sera remplacé par la configuration actuelle.',loadActive,'Recharger');else await loadActive();}
    else if(action==='undo'){if(S.undo.length)changed(S.undo.pop(),false);}
    else if(action==='validate')await validate();
    else if(action==='apply')await applyDialog();
    else if(action==='confirm'||action==='rollback')await finishTransaction(action);
    else if(action==='import'){$('#import-file').value='';$('#import-file').click();}
    else if(action==='export')exportDialog();
    else if(action==='to-visual')await toVisual();
    else if(action==='copy-code'){await navigator.clipboard.writeText(await source());toast('Code copié.');}
    else if(action==='refresh-history')await renderHistory();
    else if(action==='inspect-snapshot')await inspectSnapshot(button.dataset.id);
    else if(action==='restore-snapshot')restoreSnapshot(button.dataset.id);
  }catch(error){notice(friendly(error));}
});
document.addEventListener('change',event=>{if(event.target.id==='template-category'){T.category=event.target.value;templateCards();}if(event.target.closest('#template-parameters')){clearTimeout(T.timer);previewTemplate();}if(event.target.id==='table-select'){S.table=event.target.value;normalizeSelection();render();}if(event.target.closest('#dialog-form')){updateRuleFields();updateObjectFields();}});
document.addEventListener('input',event=>{
  if(event.target.id==='template-search')templateCardsWithQuery(event.target.value);
  if(event.target.closest('#template-parameters')){T.previewVersion++;$('#dialog-submit').disabled=true;clearTimeout(T.timer);T.timer=setTimeout(previewTemplate,300);}
  if(event.target.id==='code-editor'){
    if(S.tx&&activeStatuses.has(S.tx.status)){event.target.value=S.ir.raw_nft??S.source;return;}
    if(Date.now()-codeHistoryTime>1500){pushUndo();codeHistoryTime=Date.now();}
    S.ir={objects:[],raw_nft:event.target.value};S.source=event.target.value;S.revision++;S.validRevision=-1;S.dirty=true;saveDraft();updateChrome();
  }
  if(event.target.closest('#dialog-form')&&$('#rule-preview')){clearTimeout(previewTimer);previewTimer=setTimeout(previewRule,250);}
});
$('#import-file').addEventListener('change',event=>importFile(event.target.files[0]).catch(e=>notice(friendly(e))));
$('#logout').addEventListener('click',()=>{S.token='';S.connected=false;S.ir={objects:[],raw_nft:null};S.source='';S.tx=null;renderTransaction();render();loginDialog();});
window.addEventListener('beforeunload',event=>{if((S.dirty&&!S.persisted)||(S.tx&&activeStatuses.has(S.tx.status))){event.preventDefault();event.returnValue='';}});
setInterval(()=>{if(S.tx&&activeStatuses.has(S.tx.status))renderTransaction();},1000);
setInterval(()=>pollTransaction(),2500);
connect().catch(error=>{render();notice(friendly(error));});
