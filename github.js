// github.js
import axios from "axios";

const api = axios.create({ baseURL: "https://api.github.com", timeout: 20000 });

// Encode seguro para caminho do GitHub (mantém / entre segmentos)
const encPath = (p) => p.split("/").map(encodeURIComponent).join("/");

const rawUrl = ({ owner, repo, branch, path }) =>
  `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;

export async function getFileSha({ token, owner, repo, branch, path }) {
  const headers = { Authorization: `Bearer ${token}`, "User-Agent": "ai-orchestrator" };
  try {
    const r = await api.get(
      `/repos/${owner}/${repo}/contents/${encPath(path)}?ref=${encodeURIComponent(branch)}`,
      { headers }
    );
    return r.data.sha;
  } catch {
    return null; // arquivo não existe
  }
}

export async function putFile({ token, owner, repo, branch, path, contentBase64, message }) {
  const headers = { Authorization: `Bearer ${token}`, "User-Agent": "ai-orchestrator" };
  const sha = await getFileSha({ token, owner, repo, branch, path });

  const res = await api.put(
    `/repos/${owner}/${repo}/contents/${encPath(path)}`,
    { message, content: contentBase64, branch, sha: sha || undefined },
    { headers }
  );

  return {
    html_url: res.data.content.html_url,
    raw_url: rawUrl({ owner, repo, branch, path }),
    sha: res.data.content.sha
  };
}
