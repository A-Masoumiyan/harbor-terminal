// Preserve credentials locally in memory while upgrading an existing terminal.
export function upgradeSource(template, source, id) {
  if (typeof source !== 'string' || source.length > 1000000 || !/^[a-f0-9]{16}$/.test(id)) throw new Error('فایل قبلی معتبر نیست.');
  if (!source.includes('// Harbor Terminal ') || !source.includes(`const INSTANCE_ID = '${id}';`)) throw new Error('شناسهٔ فایل قبلی با اتصال ذخیره‌شده مطابقت ندارد.');
  const auth = source.match(/\/\/ HARBOR_AUTH_BEGIN\r?\nconst AUTH_SALT = '([a-f0-9]{32})';\r?\nconst AUTH_VERIFIER = '([a-f0-9]{64})';\r?\n\/\/ HARBOR_AUTH_END/);
  const ip = source.match(/^const ALLOWED_IP = '([0-9a-fA-F:.]*)';(?:[ \t]*\/\/[^\r\n]*)?[ \t]*$/m);
  if (!auth || !ip || !source.includes('const AUTH_ITERATIONS = 600000;')) throw new Error('قالب اطلاعات ورود قبلی شناخته نشد؛ فایل بازنویسی نشد.');
  for (const [key, value] of Object.entries({INSTANCE_ID: id, AUTH_SALT: auth[1], AUTH_VERIFIER: auth[2]})) {
    if (template.split(`__${key}__`).length !== 2) throw new Error('قالب ارتقا معتبر نیست.');
    template = template.replace(`__${key}__`, value);
  }
  if (!template.includes("const ALLOWED_IP = '';")) throw new Error('تنظیم IP قالب شناخته نشد.');
  return template.replace("const ALLOWED_IP = '';", `const ALLOWED_IP = '${ip[1]}';`);
}
