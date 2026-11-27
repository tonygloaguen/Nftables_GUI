const normalize = text => String(text).normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();

export function filterTemplates(templates, query='', category='all') {
  const words=normalize(query).trim().split(/\s+/).filter(Boolean);
  return templates.filter(template=>{
    const haystack=normalize([template.title,template.summary,template.category,template.origin,template.id].join(' '));
    return (category==='all'||template.category===category)&&words.every(word=>haystack.includes(word));
  });
}

export function templateValues(template, formValues) {
  return Object.fromEntries(template.parameters.map(p=>[p.key,String(formValues[p.key]??p.default)]));
}
