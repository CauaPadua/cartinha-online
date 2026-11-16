const COOKIE_NAME = "princesa_session";
const SESSION_SECONDS = 60 * 60 * 24 * 30;

function loginPage(message = "") {
  return new Response(`<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="theme-color" content="#fff2f6"><title>Um cantinho nosso ❤️</title>
  <style>
  *{box-sizing:border-box}body{margin:0;min-height:100svh;display:grid;place-items:center;padding:22px;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#593847;
  background:linear-gradient(150deg,#fff2f6,#fffaf2 60%,#f2eaff)}
  .card{width:min(100%,390px);padding:34px 25px;text-align:center;border:1px solid white;border-radius:30px;
  background:#ffffffdf;box-shadow:0 18px 55px #a65b7520}
  .heart{font-size:44px}small{letter-spacing:2px;text-transform:uppercase;color:#b66b86}
  h1{font:500 36px Georgia,serif;color:#a94e72;margin:12px 0}
  p{line-height:1.65;color:#806675}input{width:100%;padding:16px;border:1px solid #edc4d2;border-radius:15px;
  background:#fffafc;text-align:center;font-size:18px;margin:10px 0 14px;outline:none}
  button{width:100%;border:0;border-radius:99px;padding:15px;background:linear-gradient(100deg,#d66d91,#b96dba);
  color:white;font-size:16px;font-weight:650} .err{min-height:22px;color:#bd4569;font-size:13px}
  </style></head><body><main class="card"><div class="heart">💗</div><small>um lugarzinho especial</small>
  <h1>Oi, minha Prin!</h1><p>Tem uma surpresa esperando por você.<br>Mas antes, uma palavrinha que é só sua…</p>
  <form method="POST" action="/login"><input name="password" type="password" placeholder="Digite a palavrinha"
  autocomplete="current-password" required autofocus><button type="submit">Entrar no nosso cantinho 💌</button></form>
  <div class="err">${message}</div><small style="letter-spacing:0;text-transform:none">com carinho, só para você ✨</small>
  </main></body></html>`, {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }
  });
}

function b64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value))));
}
async function validSession(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.split(";").map(x => x.trim()).find(x => x.startsWith(COOKIE_NAME + "="));
  if (!match || !env.COOKIE_SECRET) return false;
  const token = decodeURIComponent(match.slice(COOKIE_NAME.length + 1));
  const [issued, signature] = token.split(".");
  if (!issued || !signature || !/^\d+$/.test(issued)) return false;
  const age = Math.floor(Date.now() / 1000) - Number(issued);
  if (age < 0 || age > SESSION_SECONDS) return false;
  const expected = await sign(issued, env.COOKIE_SECRET);
  return signature === expected;
}
function redirect(path, cookie) {
  const headers = new Headers({ Location: path, "Cache-Control": "no-store" });
  if (cookie) headers.append("Set-Cookie", cookie);
  return new Response(null, { status: 303, headers });
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/logout") {
      return redirect("/", `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
    }
    if (url.pathname === "/login" && request.method === "POST") {
      const form = await request.formData();
      const supplied = String(form.get("password") || "").trim().toLocaleLowerCase("pt-BR");
      const expected = String(env.SITE_PASSWORD || "princesa").trim().toLocaleLowerCase("pt-BR");
      if (supplied !== expected) return loginPage("Essa não é a palavrinha… tenta mais uma vez 💗");
      if (!env.COOKIE_SECRET) return new Response("Configuração incompleta: defina COOKIE_SECRET no painel do Worker.", { status: 503 });
      const issued = String(Math.floor(Date.now() / 1000));
      const signature = await sign(issued, env.COOKIE_SECRET);
      const cookie = `${COOKIE_NAME}=${encodeURIComponent(issued + "." + signature)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SECONDS}`;
      return redirect("/", cookie);
    }
    if (!(await validSession(request, env))) {
      if (request.method !== "GET" && request.method !== "HEAD") return new Response("Método não permitido", { status: 405 });
      return loginPage();
    }
    return env.ASSETS.fetch(request);
  }
};