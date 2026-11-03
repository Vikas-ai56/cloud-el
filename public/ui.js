// Small, consistent outline icons. All artwork is local SVG.
const paths={
 vault:'<rect x="4" y="3" width="16" height="18" rx="3"/><circle cx="12" cy="11" r="4"/><path d="M12 7v2m0 4v2m-4-4h2m4 0h2M8 21v-2m8 2v-2"/>',
 files:'<path d="M8 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-2"/><path d="M12 3h5l4 4v8a2 2 0 0 1-2 2h-7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z"/><path d="M17 3v5h4"/>',
 folder:'<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/>',
 share:'<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="m9 10 6-3M9 14l6 3"/>',
 inbox:'<path d="M4 5h16l2 11v4H2v-4L4 5Z"/><path d="M2 15h6l2 3h4l2-3h6M12 2v10m-3-3 3 3 3-3"/>',
 clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
 info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v1"/>',
 shield:'<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8.5 11.5 2.5 2.5 4.5-5"/>',
 lock:'<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
 upload:'<path d="M12 16V3m-5 5 5-5 5 5M4 16v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
 download:'<path d="M12 3v13m-5-5 5 5 5-5M4 16v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
 search:'<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
 arrow:'<path d="M5 12h14m-5-5 5 5-5 5"/>',back:'<path d="M19 12H5m5-5-5 5 5 5"/>',
 chevron:'<path d="m9 5 7 7-7 7"/>',plus:'<path d="M12 5v14M5 12h14"/>',
 refresh:'<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 7a7 7 0 0 1 12-2l2 3M4 16l2 3a7 7 0 0 0 12-2"/>',
 exit:'<path d="M9 4H4v16h5m5-12 4 4-4 4M9 12h12"/>',
 image:'<rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="8" cy="8" r="1.5"/><path d="m3 17 5-5 4 4 4-7 5 8"/>',
 audio:'<path d="M10 17V5l10-2v12M10 8l10-2"/><ellipse cx="7" cy="18" rx="3" ry="3"/><ellipse cx="17" cy="16" rx="3" ry="3"/>',
 video:'<rect x="3" y="5" width="18" height="14" rx="3"/><path d="m10 9 5 3-5 3V9Z"/>',
 document:'<path d="M13 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10l-7-7Z"/><path d="M13 3v7h7M8 14h8m-8 3h5"/>',
 database:'<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0"/>',
 eye:'<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
 check:'<path d="m5 12 4 4L19 6"/>',close:'<path d="m6 6 12 12M6 18 18 6"/>',
 code:'<path d="m8 6-6 6 6 6m8-12 6 6-6 6m-3-15-2 18"/>',
 mail:'<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 6 9 7 9-7"/>',
 restore:'<path d="M3 4v6h6"/><path d="M4 9a8 8 0 1 1 0 7M12 8v5l3 2"/>',
};
export const icon=(name,cls='')=>`<svg class="icon ${cls}" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name]||paths.document}</svg>`;
export const fileKind=f=>f.mime?.startsWith('audio/')?'audio':f.mime?.startsWith('video/')?'video':f.mime?.startsWith('image/')?'image':'document';
export const initials=email=>((email||'U').split('@')[0].slice(0,2).toUpperCase().replace(/[^A-Z0-9]/g,'' )||'SV');
