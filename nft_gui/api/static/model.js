export const clone = value => JSON.parse(JSON.stringify(value));
export function parseJsonSafely(text) {
  return JSON.parse(text,(_key,value)=>{
    if(typeof value==='number'&&(!Number.isFinite(value)||(Number.isInteger(value)&&!Number.isSafeInteger(value))))throw Error('Une valeur numérique dépasse la précision de l’éditeur. Utilisez la source .nft ou un export JSON direct du backend pour la conserver sans perte.');
    return value;
  });
}
export const actionNames = {accept:'Autoriser',drop:'Bloquer',reject:'Refuser',return:'Retour',jump:'Sauter vers',goto:'Aller vers',masquerade:'Masquerade',dnat:'DNAT',snat:'SNAT',advanced:'Avancée'};
export const kindNames = {set:'Ensemble',map:'Map',counter:'Compteur',quota:'Quota'};
export function integer(value, label, min=0, max=Number.MAX_SAFE_INTEGER) {
  if (!/^\d+$/.test(String(value)) || +value < min || +value > max) throw Error(`${label} : valeur attendue entre ${min} et ${max}.`);
  return +value;
}
export function portValue(text) {
  const parts=text.split(',').map(x=>x.trim());
  const values=parts.map(part=>{
    const bounds=part.split('-');
    if(bounds.length>2) throw Error('Port invalide. Exemple : 22, 80, 8000-8010.');
    const start=integer(bounds[0],'Port',1,65535);
    if(bounds.length===1) return start;
    const end=integer(bounds[1],'Fin de plage',start,65535);
    return {range:[start,end]};
  });
  return values.length===1 ? values[0] : {set:values};
}
export function ipValue(text) {
  const [address, mask, extra]=text.trim().split('/');
  if(extra!==undefined) throw Error('Adresse ou réseau invalide.');
  let family;
  if(address.includes(':')) {
    const halves=address.split('::');
    const groups=halves.flatMap(h=>h===''?[]:h.split(':'));
    if(halves.length>2||groups.some(g=>!/^[0-9a-fA-F]{1,4}$/.test(g))||(halves.length===1?groups.length!==8:groups.length>=8))throw Error('Adresse IPv6 invalide.');
    family='ip6';
  } else {
    if(!/^\d+\.\d+\.\d+\.\d+$/.test(address) || address.split('.').some(x=>+x>255 || (x.length>1&&x[0]==='0'))) throw Error('Adresse IPv4 invalide. Exemple : 192.168.1.0/24.');
    family='ip';
  }
  return {family, value:mask===undefined ? address : {prefix:{addr:address,len:integer(mask,'Préfixe',0,family==='ip'?32:128)}}};
}
export function addressValue(text, chain, objects) {
  if(text.startsWith('@')) {
    const set=objects.find(o=>o.kind==='set'&&o.family===chain.family&&o.table===chain.table&&o.name===text.slice(1));
    if(!set || !['ipv4_addr','ipv6_addr'].includes(set.type)) throw Error('Choisissez un ensemble d’adresses existant dans cette table.');
    const family=set.type==='ipv6_addr'?'ip6':'ip';
    if(['ip','ip6'].includes(chain.family)&&family!==chain.family) throw Error('La famille de l’ensemble ne correspond pas à la table.');
    return {family,value:text};
  }
  const items=text.split(',').map(x=>ipValue(x));
  const family=items[0].family;
  if(items.some(x=>x.family!==family)) throw Error('Séparez les adresses IPv4 et IPv6 dans deux règles.');
  if(['ip','ip6'].includes(chain.family)&&chain.family!==family) throw Error('La famille d’adresses ne correspond pas à la table.');
  return {family,value:items.length===1?items[0].value:{set:items.map(x=>x.value)}};
}
export function valueText(value) {
  if(value===null||value===undefined) return '';
  if(typeof value!=='object') return String(value);
  if(value.set) return value.set.map(valueText).join(', ');
  if(value.prefix) return `${value.prefix.addr}/${value.prefix.len}`;
  if(value.range) return value.range.map(valueText).join('-');
  return JSON.stringify(value);
}
export function decodeRule(rule) {
  const result={action:'',protocol:'any',source:'',destination:'',sport:'',dport:'',iif:'',oif:'',states:'',counter:false,log:false,logprefix:'',target:'',natAddress:'',natPort:'',comment:rule.comment||'',advanced:false};
  if(rule.raw_nft || Object.keys(rule.extra_fields||{}).length) return {...result,advanced:true,action:'advanced'};
  const seen=new Set();
  for(const expression of rule.expr||[]) {
    if(!expression.statement || expression.raw_nft || expression.unsupported_expr) {result.advanced=true;continue;}
    const [key,body]=Object.entries(expression.statement)[0];
    if(key==='match') {
      if(!body||Object.keys(body).some(k=>!['left','right','op'].includes(k))||!body.left||Object.keys(body.left).length!==1){result.advanced=true;continue;}
      if(!['==','in'].includes(body.op)) {result.advanced=true;continue;}
      let field;
      if(body.left?.payload) {
        const p=body.left.payload;
        if(Object.keys(p).some(k=>!['protocol','field'].includes(k))){result.advanced=true;continue;}
        if(['saddr','daddr'].includes(p.field)&&['ip','ip6'].includes(p.protocol)) field=p.field==='saddr'?'source':'destination';
        else if(['sport','dport'].includes(p.field)&&['tcp','udp'].includes(p.protocol)) {
          field=p.field;
          if(result.protocol!=='any'&&result.protocol!==p.protocol) result.advanced=true;
          result.protocol=p.protocol;
        }
      } else if(body.left?.meta && Object.keys(body.left.meta).length===1) {
        field={iifname:'iif',oifname:'oif',l4proto:'protocol'}[body.left.meta.key];
      } else if(body.left?.ct?.key==='state'&&Object.keys(body.left.ct).length===1) field='states';
      if(!field||seen.has(field)) {result.advanced=true;continue;}
      seen.add(field); result[field]=valueText(body.right);
    } else if(key==='counter') {
      if(typeof body==='string'||seen.has(key)) result.advanced=true;
      if(body!==null&&(typeof body!=='object'||Object.keys(body).some(k=>!['packets','bytes'].includes(k))))result.advanced=true;
      result.counter=true;seen.add(key);
    } else if(key==='log'&&body && Object.keys(body).every(k=>k==='prefix')) {
      if(seen.has(key)) result.advanced=true;
      result.log=true;result.logprefix=body.prefix||'';seen.add(key);
    } else if(['accept','drop','reject','return','jump','goto','masquerade','dnat','snat'].includes(key)) {
      if(result.action) result.advanced=true;
      result.action=key;
      if(['accept','drop','return','reject','masquerade'].includes(key)&&body!==null) result.advanced=true;
      if(['jump','goto'].includes(key)) result.target=body?.target||'';
      if(['dnat','snat'].includes(key)) {
        if(Object.keys(body).some(k=>!['family','addr','port'].includes(k))) result.advanced=true;
        result.natAddress=body.addr;result.natPort=valueText(body.port);
      }
    } else result.advanced=true;
  }
  if(!result.action) result.advanced=true;
  // The form only models predicates, then counter/log, then a terminal verdict.
  // Preserve a different statement order in the advanced editor.
  let rank=0;
  for(const e of rule.expr||[]) {
    const key=Object.keys(e.statement||{})[0];
    const next=key==='match'?0:key==='counter'?1:key==='log'?2:3;
    if(next<rank) result.advanced=true;
    rank=next;
  }
  if(!['any','tcp','udp','icmp','ipv6-icmp'].includes(result.protocol)) result.advanced=true;
  return result;
}
export function buildRule(values, chain, objects, existing=null) {
  if(!chain) throw Error('Créez d’abord une chaîne.');
  const expr=[];
  const add=statement=>expr.push({statement});
  const match=(left,right,op='==')=>add({match:{op,left,right}});
  const proto=values.protocol||'any';
  if(proto!=='any') match({meta:{key:'l4proto'}},proto);
  let addressFamily;
  for(const [input,field] of [['source','saddr'],['destination','daddr']]) {
    if(values[input]?.trim()) {
      const parsed=addressValue(values[input].trim(),chain,objects);
      if(addressFamily&&addressFamily!==parsed.family) throw Error('Source et destination doivent utiliser la même famille IP.');
      addressFamily=parsed.family;
      match({payload:{protocol:parsed.family,field}},parsed.value);
    }
  }
  for(const field of ['sport','dport']) {
    if(values[field]?.trim()) {
      if(!['tcp','udp'].includes(proto)) throw Error('Choisissez TCP ou UDP pour filtrer des ports.');
      match({payload:{protocol:proto,field}},portValue(values[field]));
    }
  }
  for(const field of ['iif','oif']) if(values[field]?.trim()) match({meta:{key:field+'name'}},values[field].trim());
  if(values.states?.trim()) {
    const states=values.states.split(',').map(x=>x.trim());
    if(states.some(x=>!['new','established','related','invalid','untracked'].includes(x))) throw Error('États disponibles : new, established, related, invalid, untracked.');
    match({ct:{key:'state'}},{set:states},'in');
  }
  if(values.counter) {
    const old=existing?.expr?.find(e=>e.statement&&'counter' in e.statement);
    add(old?.statement||{counter:null});
  }
  if(values.log) add({log:values.logprefix?{prefix:values.logprefix}:{}});
  const action=values.action;
  if(['accept','drop','reject','return','masquerade'].includes(action)) add({[action]:null});
  else if(['jump','goto'].includes(action)) {
    if(!objects.some(o=>o.kind==='chain'&&o.family===chain.family&&o.table===chain.table&&o.name===values.target&&!o.hook)) throw Error('Choisissez une chaîne régulière existante comme destination.');
    add({[action]:{target:values.target}});
  } else if(['dnat','snat'].includes(action)) {
    const parsed=ipValue(values.natAddress||'');
    if(typeof parsed.value!=='string') throw Error('La traduction NAT attend une adresse, sans préfixe.');
    const nat={addr:parsed.value};
    if(chain.family==='inet') nat.family=parsed.family;
    else if(chain.family!==parsed.family) throw Error('La famille NAT ne correspond pas à la table.');
    if(values.natPort) {
      if(!['tcp','udp'].includes(proto)) throw Error('Un port NAT exige TCP ou UDP.');
      nat.port=integer(values.natPort,'Port NAT',1,65535);
    }
    add({[action]:nat});
  } else throw Error('Action inconnue.');
  return {...(existing?clone(existing):{}),kind:'rule',family:chain.family,table:chain.table,chain:chain.name,expr,comment:values.comment?.trim()||null,raw_nft:null};
}
export function starterRuleset(web=false, ssh=false) {
  const objects=[{kind:'table',family:'inet',name:'filter'}];
  for(const hook of ['input','forward','output']) objects.push({kind:'chain',family:'inet',table:'filter',name:hook,type:'filter',hook,prio:0,policy:hook==='output'?'accept':'drop'});
  const chain=objects[1];
  const add=v=>objects.push(buildRule({action:'accept',protocol:'any',counter:true,...v},chain,objects));
  add({iif:'lo',comment:'Trafic local (loopback)'});
  add({states:'established, related',comment:'Connexions déjà établies'});
  add({protocol:'icmp',comment:'Diagnostic réseau IPv4'});
  add({protocol:'ipv6-icmp',comment:'Fonctionnement et diagnostic IPv6'});
  if(web) add({protocol:'tcp',dport:'80, 443',comment:'Serveur web HTTP / HTTPS'});
  if(ssh) add({protocol:'tcp',dport:'22',comment:'Administration SSH'});
  return {objects,raw_nft:null};
}
