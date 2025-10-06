// github.js
import axios from "axios";

const api = axios.create({
  baseURL: "https://api.github.com",
  timeout: 20000
});

function rawUrl({ owner, repo, branch, path }) {
  return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
}

export async function putFile({
  token, owner, repo, branch, path, contentBase64, message
}) {
  const headers = { Authorization: `Bearer ${token}`, "User-Agent": "orq-ia" };
  // Checa se já existe para enviar sha
  let sha;
  try {
    const r = await api.get(`/repos/${owner}/${repo}/co// github.js
import axios from "axios";

const api = axios.create({ baseURL: "https://api.github.com", timeout: 20000 });

function rawUrl({ owner, repo, branch, path }) {
  return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
}

export async function putFile({ token, owner, repo, branch, path, contentBase64, message }) {
  const headers = { Authorization: `Bearer ${token}`, "User-Agent": "ai-orchestrator" };
  let sha;
  try {
    const r = await api.get(`/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${branch}`, { headers });
    sha = r.data.sha;
  } catch {}
  const res = await api.put(
    `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`,
    { message, content: contentBase64, branch, sha },
    { headers }
  );
  return { html_url: res.data.content.html_url, raw_url: rawUrl({ owner, repo, branch, path }), sha: res.data.content.sha };
}
ntents/${encodeURIComponent(path)}?ref=${branch}`, { headers });
    sha = r.data.sha;
  } catch {}
  const res = await api.put(
    `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`,
    { message, content: contentBase64, branch, sha },
    { headers }
  );
  return {
    html_url: res.data.content.html_url,
    raw_url: rawUrl({ owner, repo, branch, path }),
    sha: res.data.content.sha
  };
}
